use yew::prelude::*;

#[function_component(Header)]
pub fn header() -> Html {
    html! {
        <header>
        <div class={classes!( "bg-cyan-500", "text-white", "dark:text-gray-500", "dark:bg-black")}>
            <div class={classes!("px-4", "py-5", "sm:px-6")}>
                <h1 id="title" class={classes!("text-lg", "font-medium", "dark:text-gray-900", "dark:text-white")}>{"Dsiem Web UI"}</h1>
            </div>
            <hr class="border-gray-200 sm:mx-auto dark:border-gray-700" />
        </div>
        </header>
    }
}
