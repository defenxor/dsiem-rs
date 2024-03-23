//! Routes by yew_router

pub mod alarm;
pub mod home;

use alarm::AlarmDetail;
use home::Home;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::{footer::Footer, header::Header};

/// App routes
#[derive(Routable, Debug, Clone, PartialEq, Eq)]
pub enum AppRoute {
    #[at("/data/alarm-detail/:alarm_id")]
    AlarmDetail { alarm_id: String },
    #[at("/")]
    Home,
    #[not_found]
    #[at("/404")]
    NotFound,
}

pub fn switch(route: AppRoute) -> Html {
    match route {
        AppRoute::AlarmDetail { alarm_id } => html! { <AlarmDetail alarm_id={alarm_id} /> },
        AppRoute::Home => html! { <Home /> },
        AppRoute::NotFound => html! {
            "Page not found"
        },
    }
}

/// The root app component
#[function_component(App)]
pub fn app() -> Html {
    html! {
        <HashRouter>
            <Header />
            <div class={classes!("min-h-screen", "text-gray-500", "dark:bg-black")}>
              <div class={classes!("px-4", "py-5", "sm:px-6")}>
                <Switch<AppRoute> render={switch} />
              </div>
            </div>
            <Footer />
        </HashRouter>
    }
}
