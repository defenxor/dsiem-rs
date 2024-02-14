use std::{ env, path::PathBuf };
use nanoid::nanoid;

fn get_dir(test_env: bool) -> Result<PathBuf, std::io::Error> {
    let dir = if test_env {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("fixtures")
    } else {
        let mut d = env::current_exe()?;
        d.pop();
        d
    };
    Ok(dir)
}

pub fn config_dir(test_env: bool, subdir: Option<Vec<String>>) -> Result<PathBuf, std::io::Error> {
    let mut dir = get_dir(test_env)?;
    dir.push("configs");
    if test_env {
        if let Some(v) = subdir {
            for d in v {
                dir.push(d);
            }
        }
    }
    Ok(dir)
}

pub fn log_dir(test_env: bool) -> Result<PathBuf, std::io::Error> {
    let mut dir = get_dir(test_env)?;
    dir.push("logs");
    Ok(dir)
}

pub fn web_dir(test_env: bool) -> Result<PathBuf, std::io::Error> {
    let mut dir = get_dir(test_env)?;
    dir.push("web");
    dir.push("dist");
    Ok(dir)
}

pub fn ref_to_digit(v: &str) -> Result<u8, String> {
    if !v.starts_with(':') {
        return Err("doesn't begin with :".to_string());
    }
    let n = v
        .replace(':', "")
        .parse::<u8>()
        .map_err(|e| e.to_string())?;
    Ok(n)
}

pub fn generate_id() -> String {
    nanoid!(9)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_ref_to_digit() {
        let res = ref_to_digit("foo");
        assert!(res.unwrap_err().contains("doesn't begin with :"));
        let res = ref_to_digit(":1");
        assert_eq!(res.unwrap(), 1);
    }
    #[test]
    fn test_generate_id() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert!(id1.len() == 9);
        assert!(id1 != id2);
    }
    #[test]
    fn test_dirs() {
        let d = config_dir(true, Some(vec!["dir".to_string(), "a".to_string()]))
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(d.contains("dsiem"));
        assert!(d.contains("fixtures"));
        assert!(d.contains("configs"));
        assert!(d.contains("dir"));

        let d = log_dir(true).unwrap().to_string_lossy().to_string();
        assert!(d.contains("dsiem"));
        assert!(d.contains("logs"));

        let d = web_dir(true).unwrap().to_string_lossy().to_string();
        assert!(d.contains("dsiem"));
        assert!(d.contains("web"));
    }
}
