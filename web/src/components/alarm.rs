use chrono::TimeZone;
use chrono::Utc;
use wasm_bindgen::JsCast;
use web_sys::window;
use web_sys::EventTarget;
use web_sys::HtmlSelectElement;
use gloo_timers::callback::Timeout;
use yew::prelude::*;
use yew_hooks::prelude::*;
use crate::services::alarm::{ self, Alarm };

#[derive(Properties, PartialEq)]
pub struct DetailProps {
    pub alarm: Alarm,
}

#[function_component(AlarmView)]
pub fn alarm_view(props: &DetailProps) -> Html {
    let a = &props.alarm;
    let toast_show = use_state(|| false);
    let toast_border = use_state(|| "border-green-500");
    let toast_text = use_state(|| "".to_string());
    let stage: UseStateHandle<u8> = use_state(|| 1);
    let status_handle = use_state(|| a.status.clone());
    let tag_handle = use_state(|| a.tag.clone());

    let update_status = use_async({
        let status = status_handle.to_string();
        let alarm_id = a.id.clone();
        let index = a.perm_index.clone();
        let search_cfg = a.search_config.clone();
        async move {
            alarm::update_field(&search_cfg, index, alarm_id, "status".to_owned(), status).await
        }
    });

    let update_tag = use_async({
        let tag = tag_handle.to_string();
        let alarm_id = a.id.clone();
        let index = a.perm_index.clone();
        let search_cfg = a.search_config.clone();
        async move {
            alarm::update_field(&search_cfg, index, alarm_id, "tag".to_owned(), tag).await
        }
    });

    let delete_alarm = use_async({
        let alarm_id = a.id.clone();
        let search_cfg = a.search_config.clone();
        async move { alarm::delete_alarm(&search_cfg, alarm_id).await }
    });

    use_effect_with_deps(
        {
            let update_status = update_status.clone();
            let toast_show = toast_show.clone();
            let toast_text = toast_text.clone();
            let toast_border = toast_border.clone();
            move |_| {
                if !update_status.loading {
                    if let Some(error) = &update_status.error {
                        toast_text.set(format!("Error changing status: {}", error));
                        toast_border.set("border-red-500");
                        toast_show.set(true);
                        Timeout::new(3000, move || {
                            toast_show.set(false);
                        }).forget();
                        return;
                    }
                    if let Some(result) = &update_status.data {
                        toast_border.set("border-green-500");
                        toast_text.set(format!("changing status result: {}", result));
                        toast_show.set(true);
                        Timeout::new(3000, move || {
                            toast_show.set(false);
                        }).forget();
                    }
                }
            }
        },
        update_status.loading
    );

    use_effect_with_deps(
        {
            let update_tag = update_tag.clone();
            let toast_show = toast_show.clone();
            let toast_text = toast_text.clone();
            let toast_border = toast_border.clone();
            move |_| {
                if !update_tag.loading {
                    if let Some(error) = &update_tag.error {
                        toast_text.set(format!("Error changing tag: {}", error));
                        toast_border.set("border-red-500");
                        toast_show.set(true);
                        Timeout::new(3000, move || {
                            toast_show.set(false);
                        }).forget();
                        return;
                    }
                    if let Some(result) = &update_tag.data {
                        toast_border.set("border-green-500");
                        toast_text.set(format!("changing tag result: {}", result));
                        toast_show.set(true);
                        Timeout::new(3000, move || {
                            toast_show.set(false);
                        }).forget();
                    }
                }
            }
        },
        update_tag.loading
    );

    use_effect_with_deps(
        {
            let delete_alarm = delete_alarm.clone();
            let toast_show = toast_show.clone();
            let toast_text = toast_text.clone();
            let toast_border = toast_border.clone();
            move |_| {
                if !delete_alarm.loading {
                    if let Some(error) = &delete_alarm.error {
                        toast_text.set(format!("Error deleting alarm: {}", error));
                        toast_border.set("border-red-500");
                        toast_show.set(true);
                        Timeout::new(3000, move || {
                            toast_show.set(false);
                        }).forget();
                        return;
                    }
                    if let Some(result) = &delete_alarm.data {
                        toast_border.set("border-green-500");
                        toast_text.set(format!("Deleting alarm result: {}", result));
                        toast_show.set(true);
                        Timeout::new(3000, move || {
                            toast_show.set(false);
                            if let Some(window) = window() {
                                _ = window.close();
                            }
                        }).forget();
                    }
                }
            }
        },
        delete_alarm.loading
    );

    let on_status_change = {
        let status_handle = status_handle;
        let update_status = update_status.clone();
        Callback::from(move |e: Event| {
            let target: Option<EventTarget> = e.target();
            let input: Option<HtmlSelectElement> = target.and_then(|t|
                t.dyn_into::<HtmlSelectElement>().ok()
            );
            if let Some(input) = input {
                status_handle.set(input.value());
                update_status.run();
            }
        })
    };

    let on_tag_change = {
        let tag_handle = tag_handle;
        let update_tag = update_tag.clone();
        Callback::from(move |e: Event| {
            let target: Option<EventTarget> = e.target();
            let input: Option<HtmlSelectElement> = target.and_then(|t|
                t.dyn_into::<HtmlSelectElement>().ok()
            );
            if let Some(input) = input {
                tag_handle.set(input.value());
                update_tag.run();
            }
        })
    };

    let on_delete = {
        Callback::from(move |_| {
            delete_alarm.run();
        })
    };

    html! {
        <div>
            <div class={classes!("p-8")}>

            {
                if *toast_show {
                    html! {
                        <div id="myToast" class={classes!(*toast_border,"fixed", "right-10", "top-10", "px-5", "py-4", "border-r-8", "bg-white", "drop-shadow-lg")}>
                        <p class={classes!("text-sm")}>
                        {&*toast_text.clone()}
                        </p>
                         </div>
                    }
                } else {
                    html!{}
                }
            }

            // title
            <div class={classes!("px-4", "py-5", "sm:px-6")}>
                <h2 id="title" class={classes!("text-lg", "font-medium", "text-gray-900", "dark:text-white")}>{a.title.clone()}
                {
                    if update_status.loading || update_tag.loading {
                        html! {<span class={classes!("loading", "dots")}>{"\u{00a0}\u{00a0}\u{00a0}"}</span>}
                    } else {
                        html!{}
                    }
                }
                </h2>
            </div>
            <div class={classes!("px-4", "sm:px-6")}>
            <div class={classes!("relative","overflow-x-auto","sm:rounded-lg")}>
            <table class={classes!("w-full","text-sm", "text-left", "text-gray-500", "dark:text-gray-400", "border-2", "dark:border-0")}>
                <thead class={classes!("text-xs","text-gray-700", "uppercase", "bg-orange-100", "dark:bg-gray-700", "dark:text-gray-400")}>
                    <tr>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Alarm ID"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Created"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Updated"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Status"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Risk"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Tag"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Sources"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Destinations"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Action"}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr class={classes!("bg-white","border-b", "dark:bg-gray-900", "dark:border-gray-700")}>
                        <td class={classes!("px-6","py-4")}>{a.id.clone()}</td>
                        <td class={classes!("px-6","py-4")}>{a.timestamp.with_timezone(&chrono::Local)}</td>
                        <td class={classes!("px-6","py-4")}>{a.updated_time.with_timezone(&chrono::Local)}</td>
                        <td class={classes!("px-6","py-4")}>
                        <select name="status" id="status" onchange={on_status_change}>
                        {
                            a.status_selection.clone().into_iter().map(|s| {
                                html!{
                                    <option value={s.clone()} label={s.clone()} selected={s == a.status.clone()}/>
                                }
                            }).collect::<Html>()
                        }
                        </select>
                        </td>
                        <td class={classes!("px-6","py-4")}>{a.risk_class.clone()}</td>
                        <td class={classes!("px-6","py-4")}>
                        <select name="tag" id="tag" onchange={on_tag_change}>
                        {
                            a.tag_selection.clone().into_iter().map(|t| {
                                html!{
                                    <option value={t.clone()} label={t.clone()} selected={t == a.tag.clone()}/>
                                }
                            }).collect::<Html>()
                        }
                        </select>
                        
                        </td>
                        <td class={classes!("px-6","py-4")}>{a.src_ips.clone()}</td>
                        <td class={classes!("px-6","py-4")}>{a.dst_ips.clone()}</td>
                        <td class={classes!("px-6","py-4")}><button id="delete" onclick={on_delete}>{"Delete"}</button></td>
                    </tr>
                </tbody>
            </table>
            </div>
            </div>

            // rules
            <div class={classes!("px-4", "py-5", "sm:px-6")}>
            <h4 class={classes!( "font-medium", "leading-6", "text-gray-900", "dark:text-white/75")}>{"Rules"}</h4>
            </div>
            <div class={classes!("px-4", "sm:px-6")}>
            <div class={classes!("relative","overflow-x-auto","sm:rounded-lg")}>
            <table class={classes!("w-full","text-sm", "text-left", "text-gray-500", "dark:text-gray-400", "border-2", "dark:border-0")}>
                <thead class={classes!("text-xs","text-gray-700", "uppercase", "bg-orange-100", "dark:bg-gray-700", "dark:text-gray-400")}>
                    <tr>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Corr. stage"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Started"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Ended"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Status"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Name"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"From"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"To"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Protocol"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Port From"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Port To"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Events"}</th>
                    </tr>
                </thead>
                <tbody>
                    {
                        a.rules.clone().into_iter().map(|r| {
                        html!{
                            <tr key={r.stage} class={classes!("bg-white","border-b", "dark:bg-gray-900", "dark:border-gray-700")}>
                                <td class={classes!("px-6","py-4")}><button class={classes!("btn","rounded")} onclick={ let stage = stage.clone();
                                    Callback::from(move |_| stage.set(r.stage))}><u>{r.stage}</u></button></td>
                                <td class={classes!("px-6","py-4")}>{
                                    if r.start_time == 0 {
                                        html!{"-"}
                                    } else {
                                        html!{Utc.timestamp_opt(r.start_time as i64, 0).unwrap().with_timezone(&chrono::Local)}
                                    }
                                }</td>
                                <td class={classes!("px-6","py-4")}>{
                                    if r.end_time == 0 {
                                        html!{"-"}
                                    } else {
                                        html!{Utc.timestamp_opt(r.end_time as i64, 0).unwrap().with_timezone(&chrono::Local)}
                                    }
                                }
                                </td>
                                <td class={classes!("px-6","py-4")}>{r.status}</td>
                                <td class={classes!("px-6","py-4")}>{r.name}</td>
                                <td class={classes!("px-6","py-4")}>{r.from}</td>
                                <td class={classes!("px-6","py-4")}>{r.to}</td>
                                <td class={classes!("px-6","py-4")}>{r.protocol}</td>
                                <td class={classes!("px-6","py-4")}>{r.port_from}</td>
                                <td class={classes!("px-6","py-4")}>{r.port_to}</td>
                                <td class={classes!("px-6","py-4")}>{r.ttl_matched}{"/"}{r.occurrence}</td>
                            </tr>}
                        }).collect::<Html>()
                    }
                </tbody>
            </table>
            </div>
            </div>

            // vulnerabilities
            { if !a.vulnerabilities.is_empty() {
                html!{
                <div>
                <div class={classes!("px-4", "py-5", "sm:px-6")}>
                    <h5 class={classes!( "font-medium", "leading-6", "text-gray-900", "dark:text-white/75")}>{"Vulnerabilities"}</h5>
                </div>
                <div class={classes!("px-4", "sm:px-6")}>
                <div class={classes!("relative","overflow-x-auto","sm:rounded-lg")}>
                <table class={classes!("w-full","text-sm", "text-left", "text-gray-500", "dark:text-gray-400", "border-2", "dark:border-0")}>
                    <thead class={classes!("text-xs","text-gray-700", "uppercase", "bg-orange-100", "dark:bg-gray-700", "dark:text-gray-400")}>
                        <tr>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Provider"}</th>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Term"}</th>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Result"}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            a.vulnerabilities.clone().into_iter().map(|v| {
                            html!{
                                <tr class={classes!("bg-white","border-b", "dark:bg-gray-900", "dark:border-gray-700")}>
                                    <td class={classes!("px-6","py-4")}>{v.provider}</td>
                                    <td class={classes!("px-6","py-4")}>{v.term}</td>
                                    <td class={classes!("px-6","py-4")}>{v.result}</td>
                                </tr>}
                            }).collect::<Html>()
                        }
                    </tbody>
                </table>
                </div>
                </div>
                </div>
                }
            } else {
                html!{}
            }}

            // threat intel
            { if !a.intel_hits.is_empty() {
                html!{
                <div>
                <div class={classes!("px-4", "py-5", "sm:px-6")}>
                    <h5 class={classes!( "font-medium", "leading-6", "text-gray-900", "dark:text-white/75")}>{"Threat Intelligence"}</h5>
                </div>
                <div class={classes!("px-4", "sm:px-6")}>
                <div class={classes!("relative","overflow-x-auto","sm:rounded-lg")}>
                <table class={classes!("w-full","text-sm", "text-left", "text-gray-500", "dark:text-gray-400", "border-2", "dark:border-0")}>
                    <thead class={classes!("text-xs","text-gray-700", "uppercase", "bg-orange-100", "dark:bg-gray-700", "dark:text-gray-400")}>
                        <tr>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Provider"}</th>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Term"}</th>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Result"}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            a.intel_hits.clone().into_iter().map(|i| {
                            html!{
                                <tr class={classes!("bg-white","border-b", "dark:bg-gray-900", "dark:border-gray-700")}>
                                    <td class={classes!("px-6","py-4")}>{i.provider}</td>
                                    <td class={classes!("px-6","py-4")}>{i.term}</td>
                                    <td class={classes!("px-6","py-4")}>{i.result}</td>
                                </tr>}
                            }).collect::<Html>()
                        }
                    </tbody>
                </table>
                </div>
                </div>
                </div>
                }
            } else {
                html!{}
            }}

            // custom data
            { if !a.custom_data.is_empty() {
                html!{
                <div>
                <div class={classes!("px-4", "py-5", "sm:px-6")}>
                    <h5 class={classes!( "font-medium", "leading-6", "text-gray-900", "dark:text-white/75")}>{"Custom Data"}</h5>
                </div>
                <div class={classes!("px-4", "sm:px-6")}>
                <div class={classes!("relative","overflow-x-auto","sm:rounded-lg")}>
                <table class={classes!("w-full","text-sm", "text-left", "text-gray-500", "dark:text-gray-400", "border-2", "dark:border-0")}>
                    <thead class={classes!("text-xs","text-gray-700", "uppercase", "bg-orange-100", "dark:bg-gray-700", "dark:text-gray-400")}>
                        <tr>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Label"}</th>
                            <th scope="col" class={classes!("px-6","py-3")}>{"Content"}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            a.custom_data.clone().into_iter().map(|c| {
                            html!{
                                <tr class={classes!("bg-white","border-b", "dark:bg-gray-900", "dark:border-gray-700")}>
                                    <td class={classes!("px-6","py-4")}>{c.label}</td>
                                    <td class={classes!("px-6","py-4")}>{c.content}</td>
                                </tr>}
                            }).collect::<Html>()
                        }
                    </tbody>
                </table>
                </div>
                </div>
                </div>
                }
            } else {
                html!{}
            }}

            // events
            <div class={classes!("px-4", "py-5", "sm:px-6")}>
                <h5 class={classes!( "font-medium", "leading-6", "text-gray-900", "dark:text-white/75")}>{"Events"}</h5>
            </div>
            <div class={classes!("px-4", "sm:px-6")}>
            <div class={classes!("relative","overflow-x-auto","sm:rounded-lg")}>
            { if a.events.clone().into_iter().any(|e| e.stage == *stage) {
                html!{
            <table class={classes!("w-full","text-sm", "text-left", "text-gray-500", "dark:text-gray-400", "border-2", "dark:border-0")}>
                <thead class={classes!("text-xs","text-gray-700", "uppercase", "bg-orange-100", "dark:bg-gray-700", "dark:text-gray-400")}>
                    <tr>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Event ID"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Timestamp"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Title"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Source"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Destination"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Protocol"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Port From"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Port To"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Sensor"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Plugin"}</th>
                        <th scope="col" class={classes!("px-6","py-3")}>{"Plugin SID"}</th>
                    </tr>
                </thead>
                <tbody>
                    {
                        a.events.clone().into_iter().filter(|e| e.stage == *stage).map(|e| {
                        html!{
                            <tr key={e.event_id.clone()} class={classes!("bg-white","border-b", "dark:bg-gray-900", "dark:border-gray-700")}>
                                <td class={classes!("px-6","py-4")}>{e.event_id}</td>
                                <td class={classes!("px-6","py-4")}>{e.timestamp.with_timezone(&chrono::Local)}</td>
                                <td class={classes!("px-6","py-4")}>{e.title}</td>
                                <td class={classes!("px-6","py-4")}>{e.src_ip}</td>
                                <td class={classes!("px-6","py-4")}>{e.dst_ip}</td>
                                <td class={classes!("px-6","py-4")}>{e.protocol}</td>
                                <td class={classes!("px-6","py-4")}>{e.src_port}</td>
                                <td class={classes!("px-6","py-4")}>{e.dst_port}</td>
                                <td class={classes!("px-6","py-4")}>{e.sensor}</td>
                                <td class={classes!("px-6","py-4")}>{e.plugin_id}</td>
                                <td class={classes!("px-6","py-4")}>{e.plugin_sid}</td>
                            </tr>}
                        }).collect::<Html>()
                    }
                </tbody>
            </table>
            }} else {
                html!{<p>{"Cannot find matching event"}</p>}
            }
            }
            </div>
            </div>
            </div>
            <br/><br/>
         
        </div>
    }
}
