use yew::prelude::*;
use crate::services::config::{ DSIEM_CONFIG_URL, ES_CONFIG_URL };

/// Home page with an article list and a tag list.
#[function_component(Home)]
pub fn home() -> Html {
    let location = yew_hooks::use_location();
    let dsiem_config_url =
        location.protocol.clone() + "//" + &location.host.clone() + DSIEM_CONFIG_URL;
    let es_config_url = location.protocol.clone() + "//" + &location.host.clone() + ES_CONFIG_URL;

    html! {
        <div class="home-page">
            <div class="container page">
                <div class="mb-4">
                  {"This app shows an alarm relation to it's associated rules and events, and provides a way to update the status and tag of the alarm. "}
                  {"This should mainly be opened by clicking on "}<code>{ "Dsiem Link" }</code>{" on the Kibana dashboard."}
                </div>
                <div class="mb-4">
                  {"Requirements: "}
                </div>
                <div class="ml-4 mb-4">
                  <ul class="list-disc">
                    <li>{"Dsiem config file must be accessible from "}<a href={dsiem_config_url.clone()}>{dsiem_config_url.clone()}</a></li>
                    <li>{"ES config file must be accessible from "} <a href={es_config_url.clone()}>{es_config_url.clone()}</a></li>
                  </ul>
                </div>
                <div class="mb-4">
                  {"Dsiem config file should be created automatically by the frontend node when "}<code>{"WRITEABLE_CONFIG"}</code> {" environment variable is set to true. "}
                  {"ES config file should be created automatically by the frontend node based on "}<code>{"DSIEM_WEB_ESURL"}</code> {" and "}<code>{"DSIEM_WEB_KBNURL"}</code> {" environment variables."}
                </div>                
                <div class="mb-4">
                  {"Refer to the example "}<b><a href={"https://github.com/defenxor/dsiem/tree/master/deployments/docker"}>{"docker-compose files"}</a></b>{" on how to set those environment variables."}
                </div>
            </div>
        </div>
    }
}
