use yew::prelude::*;
use yew_hooks::prelude::*;

use crate::{components::alarm::AlarmView, services::alarm};

#[derive(Properties, PartialEq)]
pub struct DetailProps {
    pub alarm_id: String,
}

#[function_component(AlarmDetail)]
pub fn alarm_detail(props: &DetailProps) -> Html {
    let loaded = use_state(|| false);
    let location = yew_hooks::use_location();
    let alarm_id = props.alarm_id.clone();

    let state = use_async({
        let alarm_id = alarm_id.clone();
        let url = location.protocol.clone() + "//" + &location.host.clone();
        async move { alarm::read(url, alarm_id).await }
    });

    let handle = state.clone();
    use_effect_with_deps(
        move |_| {
            let handle = handle;
            handle.run();
        },
        loaded,
    );

    html! {
        <div class={classes!("min-h-screen", "bg-white", "dark:bg-black")}>
            {
                if state.loading {
                    html! {
                        <div class={classes!("loading", "dots", "bg-white", "dark:bg-black")}>
                            {"\u{00a0}\u{00a0}\u{00a0}"}
                        </div>
                    }
                } else {
                    html! {}
                }
            }
            {
                if let Some(error) = &state.error {
                    let msg = format!("Cannot read alarm ID: {}, Error: {}", alarm_id.clone(), error);
                    html! {msg}
                } else {
                    html! {}
                }
            }
            {
                if let Some(data) = &state.data {
                    html! { <AlarmView alarm={data.clone()}/> }
                } else {
                    html! {}
                }
            }
        </div>
    }
}
