// wasm-pack test --chrome --headless

use std::time::Duration;

use dsiem_ui::app::App;
use wasm_bindgen_test::*;
use yew::platform::time::sleep;
// use dsiem_ui::app::alarm;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_home_page() {
    yew::Renderer::<App>::with_root(gloo_utils::document().get_element_by_id("output").unwrap()).render();

    sleep(Duration::new(2, 0)).await;
    let result = gloo_utils::document().body().unwrap().inner_html();
    assert!(result.contains(
        "This app shows an alarm relation to it's associated rules and events, and provides a way to update the \
         status and tag of the alarm."
    ));
}
