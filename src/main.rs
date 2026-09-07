#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ghost_chat_cleaner::app::GhostChatApp;
use ghost_chat_cleaner::app_state::RunMode;

fn main() -> eframe::Result {
    let run_mode = if std::env::args()
        .skip(1)
        .any(|argument| argument == "--demo")
    {
        RunMode::Demo
    } else {
        RunMode::Live
    };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([840.0, 660.0])
            .with_min_inner_size([720.0, 580.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "Ghost Chat Cleaner",
        options,
        Box::new(move |creation_context| {
            Ok(Box::new(GhostChatApp::new(
                &creation_context.egui_ctx,
                run_mode,
            )?))
        }),
    )
}
