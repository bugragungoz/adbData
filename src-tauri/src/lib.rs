//! The adbData window and the commands it calls. Everything about adb and Android lives in
//! `adbdata-core`; this crate wires it to Tauri.

mod commands;
mod settings;
mod state;

use std::sync::Arc;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Two windows would copy to the same phone at once; show the first instead.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let config_dir = app.path().app_config_dir().ok();
            let data_dir = app.path().app_local_data_dir()?;
            let default_destination = app
                .path()
                .desktop_dir()
                .or_else(|_| app.path().home_dir())?
                .join("adbData");
            app.manage(Arc::new(state::AppState::new(
                config_dir,
                data_dir,
                default_destination,
            )));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_phone,
            commands::list_folder,
            commands::get_places,
            commands::plan_pull_copy,
            commands::plan_push_copy,
            commands::start_copy,
            commands::stop_copy,
            commands::get_copy,
            commands::get_history,
            commands::clear_history,
            commands::download_platform_tools,
            commands::get_settings,
            commands::set_settings,
        ])
        .run(tauri::generate_context!())
        .expect("adbData could not start");
}
