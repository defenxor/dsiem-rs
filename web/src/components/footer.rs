use yew::prelude::*;

#[function_component(Footer)]
pub fn footer() -> Html {
    html! {
        <footer class="bg-gray-200 dark:bg-gray-900">
        <hr class="border-gray-200 sm:mx-auto dark:border-gray-700" />
        <div class={classes!("px-4", "py-5", "sm:px-6")}>
          <div class="sm:flex sm:items-center sm:justify-between">
              <span class="text-sm sm:text-center dark:text-gray-400">{ " © 2024 " }
                <a href="https://github.com/defenxor/dsiem" class="hover:underline">{ "Dsiem Authors" }</a>
              </span>
          </div>
        </div>
    </footer>
      }
}
