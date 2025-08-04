// Run with: wasm-pack test --chrome --headless
// or: wasm-pack test --firefox --headless

#![allow(dead_code)]

use dsiem_ui::app::App;
use gloo_console::log;
use gloo_timers::future::TimeoutFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_home_page() {
    // Create a div element for the app to render into
    let document = gloo_utils::document();
    let output_div = document.create_element("div").unwrap();
    output_div.set_id("output");
    document.body().unwrap().append_child(&output_div).unwrap();

    // Render the app
    yew::Renderer::<App>::with_root(output_div).render();

    // Wait for rendering to complete
    TimeoutFuture::new(2000).await;

    // Check that the home page content is rendered
    let result = document.body().unwrap().inner_html();

    // Debug: log the actual HTML content
    log!("Rendered HTML:", &result);

    // Test for the main description text (be more flexible with whitespace and
    // formatting)
    let normalized_result = result.replace('\n', " ").replace("  ", " ");

    // Test the core message is present (split into smaller, more reliable parts)
    assert!(normalized_result.contains("This app shows an alarm relation"));
    assert!(normalized_result.contains("associated rules and events"));
    assert!(normalized_result.contains("update the status and tag"));

    // Test for other key elements
    assert!(normalized_result.contains("Requirements"));
    assert!(normalized_result.contains("Dsiem config file"));
    assert!(normalized_result.contains("ES config file"));
}

#[wasm_bindgen_test]
async fn test_app_structure() {
    // Create a div element for the app to render into
    let document = gloo_utils::document();
    let output_div = document.create_element("div").unwrap();
    output_div.set_id("output-structure");
    document.body().unwrap().append_child(&output_div).unwrap();

    // Render the app
    yew::Renderer::<App>::with_root(output_div).render();

    // Wait for rendering to complete
    TimeoutFuture::new(2000).await;

    // Check that basic app structure is present
    let result = document.body().unwrap().inner_html();

    // Should have the main container classes
    assert!(result.contains("min-h-screen"));
    assert!(result.contains("text-gray-500"));
}

#[wasm_bindgen_test]
fn test_app_can_be_created() {
    // Simple test to ensure the App component can be instantiated
    let document = gloo_utils::document();
    let output_div = document.create_element("div").unwrap();
    output_div.set_id("output-simple");
    document.body().unwrap().append_child(&output_div).unwrap();

    // This should not panic
    yew::Renderer::<App>::with_root(output_div).render();
}
