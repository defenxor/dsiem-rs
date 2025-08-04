// This test spawns nats, nesd, and wise using docker-compose, copies configs
// from fixtures, and then runs dsiem-frontend and dsiem-backend binaries in
// debug directory. It then sends events matching the directives to the
// frontend, and verifies the results in siem_alarms and siem_alarm_events logs.

// to add more directives, add them to the directive7 directory in fixtures, and
// update the expected_table in test_directives_result below.

use std::{
    collections::HashSet,
    env::current_exe,
    fs,
    io::Write,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::Duration,
};

use colored::Colorize;
use dsiem::{backlog::Backlog, directive::Directive, event::NormalizedEvent};
use table_test::table_test;

// as defined in the compose file
const NESD_PORT: u16 = 18082;
const WISE_PORT: u16 = 18081;
const NATS_PORT: u16 = 42227;

// frontend port to use
const FRONTEND_PORT: u16 = 18080;

mod generator;

struct ComposeCleaner {}
impl Drop for ComposeCleaner {
    fn drop(&mut self) {
        let test_dir_str = get_test_dir().to_string_lossy().to_string();
        assert!(run_in_shell("docker compose down -v", &test_dir_str, "failed to run docker compose down").success());
    }
}

#[derive(Default)]
struct BinSpawner {
    frontend: Option<std::process::Child>,
    backend: Option<std::process::Child>,
}
impl Drop for BinSpawner {
    fn drop(&mut self) {
        if let Some(f) = &mut self.frontend {
            assert!(f.kill().is_ok());
            assert!(f.wait().is_ok());
        }
        if let Some(b) = &mut self.backend {
            assert!(b.kill().is_ok());
            assert!(b.wait().is_ok());
        }
    }
}

fn print(msg: &str, exclude_newline: bool) {
    if exclude_newline {
        print!("{}", msg.bold().green());
    } else {
        println!("{}", msg.bold().green());
    }
}

fn local_listener_ready(port: u16) -> bool {
    let addr = SocketAddr::from((IpAddr::V4("127.0.0.1".parse().unwrap()), port));
    TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
}

#[test]
fn test_e2e_frontend_nats_backend() {
    prep_files();

    let test_dir_str = get_test_dir().to_string_lossy().to_string();
    let directives = load_directives(&test_dir_str);

    let _cleaner = ComposeCleaner {};

    assert!(run_in_shell("docker compose up -d", &test_dir_str, "failed to run docker compose up").success());

    print("waiting for docker services to start", false);
    sleep(Duration::from_secs(1));

    print("checking if services ports are open", false);
    for port in &[NESD_PORT, WISE_PORT, NATS_PORT] {
        print(&format!("checking port {port} .. "), true);
        assert!(local_listener_ready(*port));
        print("up", false);
    }

    let mut dsiem_cleaner = BinSpawner::default();

    print("running dsiem-frontend", false);
    // add -vv before serve for more verbose output
    let frontend_cmd = format!(
        "exec ./dsiem-frontend serve -n frontend --msq nats://127.0.0.1:{NATS_PORT}/ -a 0.0.0.0 -p {FRONTEND_PORT}"
    );
    let frontend = spawn_in_shell(&frontend_cmd, &test_dir_str, "failed to run dsiem-frontend");
    dsiem_cleaner.frontend = Some(frontend);

    sleep(Duration::from_secs(1));
    print("checking if frontend port is open .. ", true);
    assert!(local_listener_ready(FRONTEND_PORT));
    print("up", false);

    print("running dsiem-backend", false);
    // add -vv before serve for more verbose output
    let backend_cmd = format!(
        "exec ./dsiem-backend serve -n dsiem-backend-0 --msq nats://127.0.0.1:{NATS_PORT} \
         -f http://127.0.0.1:{FRONTEND_PORT} --intel_private_ip"
    );
    let backend = spawn_in_shell(&backend_cmd, &test_dir_str, "failed to run dsiem-backend");
    dsiem_cleaner.backend = Some(backend);

    print("waiting for services to start", false);
    sleep(Duration::from_secs(3));

    test_directives_result(&directives);
    print(&format!("\nDone, each directive log files available in {test_dir_str}/logs for more details\n"), false);
}

fn test_directives_result(directives: &[Directive]) {
    let test_dir = get_test_dir().to_string_lossy().to_string();

    // this is the expected result for each directive

    let expected_table: Vec<(u64, (usize, u8, usize, usize))> = vec![
        // directive id, (alarm entries, risk, intel_hits, vulnerabilities)
        (1, (3, 10, 1, 0)), // all 3 rules should be finished, and risk hit the highest value
        (2, (3, 10, 1, 0)), // same as above
        (3, (3, 10, 1, 1)), // same as above, but there's an entry in vulnerabilities
        (4, (2, 5, 1, 0)),  /* the last rule has sticky_diff to DST_IP, while event's DST_IP is fixed to a single IP
                             * (HOME_NET) */
        (5, (2, 4, 0, 0)), /* all 3 rules should be finished, but risk is only > 1 at stage 2 and stage 3. Also
                            * there's no entry in intel */
    ];

    for (validator, dir_id, expected) in table_test!(expected_table) {
        let actual = test_directive(dir_id, directives, &test_dir);

        validator
            .given(&format!("directive id: {dir_id}, "))
            .when("test_directive")
            .then(&format!(
                "it should be alarm entries: {}, risk: {}, intel_hits: {}, vulnerabilities: {}",
                expected.0, expected.1, expected.2, expected.3
            ))
            .assert_eq(expected, actual);
    }
}

fn test_directive(id: u64, directives: &[Directive], test_dir: &str) -> (usize, u8, usize, usize) {
    let d = directives.iter().find(|d| d.id == id).expect("failed to find directive");

    print(&format!("\ngenerating and sending events for directive id: {} name: {}\n", d.id, d.name), false);
    send_events_to_frontend(d);
    sleep(Duration::from_secs(3));

    let alarms = read_alarms();

    // there should only be entries for a single alarm
    let uniq_ids = alarms.iter().map(|a| a.id.as_str()).collect::<HashSet<&str>>();
    assert_eq!(uniq_ids.len(), 1);

    let risk = alarms.iter().last().unwrap().risk.load(std::sync::atomic::Ordering::Relaxed);
    let intel_hits = alarms.iter().last().unwrap().intel_hits.lock().len();
    let vulnerabilities = alarms.iter().last().unwrap().vulnerabilities.lock().len();

    let cp_n_rm = format!(
        "cp logs/siem_alarms.json logs/siem_alarms_{}.json && cp logs/siem_alarm_events.json \
         logs/siem_alarm_events_{}.json && rm logs/siem_alarms.json && rm logs/siem_alarm_events.json",
        d.id, d.id
    );
    let res = run_in_shell(&cp_n_rm, test_dir, "failed to cp and truncate log files");
    assert!(res.success());
    (alarms.len(), risk, intel_hits, vulnerabilities)
}

fn read_alarms() -> Vec<Backlog> {
    let test_dir = get_test_dir();
    let file = test_dir.join("logs").join("siem_alarms.json");
    let content = fs::read_to_string(file).expect("failed to read siem_alarms.json");
    let mut res = vec![];
    for line in content.lines() {
        let b: Backlog = serde_json::from_str(line).expect("failed to parse siem_alarms.json");
        res.push(b);
    }
    res
}

fn send_events_to_frontend(d: &Directive) {
    let events = generator::generate_normalized_event(&d.rules);
    write_events_to_disk(d.id, &events);
    for e in events {
        print("sending event:", false);
        println!("{}", serde_json::to_string(&e).unwrap());
        let client = reqwest::blocking::Client::new();
        let res = client.post(format!("http://localhost:{FRONTEND_PORT}/events/")).json(&e).send().unwrap();
        sleep(Duration::from_millis(100));
        assert!(res.status().is_success());
    }
}

fn write_events_to_disk(dir_id: u64, events: &[NormalizedEvent]) {
    let test_dir = get_test_dir();
    let filename = format!("siem_events_{dir_id}.json");
    let file = test_dir.join("logs").join(filename);
    let mut f = fs::File::create(file).expect("failed to create events.json");
    for e in events {
        let s = serde_json::to_string(&e).expect("failed to serialize event") + "\n";
        f.write_all(s.as_bytes()).expect("failed to write event to file");
    }
}

fn load_directives(test_dir: &str) -> Vec<Directive> {
    let v = vec![test_dir.to_string(), "configs".to_string()];
    dsiem::directive::load_directives(true, Some(v)).unwrap()
}

fn run_in_shell(cmd: &str, dir: &str, fail_msg: &str) -> std::process::ExitStatus {
    let cmd = format!("cd {dir} && {cmd}");
    let out = Command::new("sh").arg("-c").arg(cmd).output().expect(fail_msg);
    out.status
}

fn spawn_in_shell(cmd: &str, dir: &str, fail_msg: &str) -> std::process::Child {
    let cmd = format!("cd {dir} && {cmd}");
    let out = Command::new("sh").arg("-c").arg(cmd).spawn().expect(fail_msg);
    out
}

fn get_test_dir() -> PathBuf {
    // this should be in deps
    let current_exe = current_exe().unwrap();
    // get to debug
    let debug_dir = current_exe.parent().unwrap().parent().expect("Failed to get debug dir");
    debug_dir.to_owned()
}

fn clear_logs() {
    let test_dir = get_test_dir();
    let logs_dir = test_dir.join("logs");
    let _ = fs::remove_dir_all(&logs_dir);
    fs::create_dir_all(&logs_dir).expect("Failed to create logs dir");
}

fn prep_files() {
    let debug_dir = get_test_dir();

    // ensure that the binaries are in the debug dir
    for bin in &["dsiem-backend", "dsiem-frontend"] {
        assert!(Path::exists(&debug_dir.join(bin)));
    }

    // get to test fixtures directory
    let root_dir = if debug_dir.ends_with("dsiem-rs/target/debug") {
        // for cargo test/nextest
        debug_dir.parent().unwrap().parent().unwrap()
    } else {
        // for cargo llvm-cov test/nextest
        debug_dir.parent().unwrap().parent().unwrap().parent().unwrap()
    };
    let src_conf_dir = root_dir.join("fixtures").join("configs");
    assert!(Path::exists(&src_conf_dir));

    // create configs dir
    let config_dir = debug_dir.join("configs");
    let _ = fs::remove_dir_all(&config_dir);
    fs::create_dir_all(&config_dir).expect("Failed to create configs dir");

    // copy assets.json
    let conf_dir = debug_dir.join("configs").to_string_lossy().to_string() + "/";
    let out = Command::new("cp")
        .arg("-r")
        .arg(src_conf_dir.join("assets").join("assets_testing.json"))
        .arg(&conf_dir)
        .output()
        .expect("Failed to copy assets.json");
    assert!(out.status.success());

    // copy directives.json
    let cp_directives_cmd = format!("cp -r {}/directives/directive7/* {}", src_conf_dir.to_string_lossy(), conf_dir);
    let out = run_in_shell(&cp_directives_cmd, &src_conf_dir.to_string_lossy(), "Failed to copy directives files");
    assert!(out.success());

    // copy intel & vulns .json
    let cp_intel_vuln_cmd = format!("cp -r {}/intel_vuln/* {}", src_conf_dir.to_string_lossy(), conf_dir);
    let out = run_in_shell(&cp_intel_vuln_cmd, &src_conf_dir.to_string_lossy(), "Failed to copy intel and vuln files");
    assert!(out.success());

    // copy compose files
    let compose_glob = src_conf_dir.parent().unwrap().join("compose").to_string_lossy().to_string() + "/*";
    let compose_dir = debug_dir.to_string_lossy().to_string() + "/";
    let cp_cmd = "cp -r ".to_string() + &compose_glob + " " + &compose_dir;
    let out = Command::new("sh").arg("-c").arg(cp_cmd).output().expect("Failed to copy compose files");
    assert!(out.status.success());

    // make sure logs dir exist and is empty
    clear_logs();
}
