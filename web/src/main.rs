pub mod app;
mod components;
mod services;

fn main() {
    yew::Renderer::<app::App>::new().render();
}
