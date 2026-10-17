//! Against Google's real platform-tools. Ignored by default (it downloads them); CI runs it with
//! --include-ignored.

use adbdata_core::fetch::fetch;
use adbdata_core::runner::Adb;
use adbdata_core::tools::{install, DOWNLOAD_URL};
use adbdata_core::wire::Server;

#[test]
#[ignore = "downloads platform-tools from Google"]
fn the_real_adb_server_answers_our_requests() {
    let mut last = (0, None);
    let zip = fetch(DOWNLOAD_URL, 200_000_000, &mut |done, total| last = (done, total)).unwrap();
    assert_eq!(last.0, zip.len() as u64);
    let dir = std::env::temp_dir().join(format!("adbdata-net-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let adb = Adb::new(install(&zip, &dir).unwrap());
    let version = adb.version().unwrap();
    assert!(version.split('.').count() >= 3, "{version}");

    // A port of its own, so a server already running on this computer is left alone.
    let port = 5199;
    std::env::set_var("ANDROID_ADB_SERVER_PORT", port.to_string());
    adb.start_server().unwrap();
    let server = Server::on_port(port);
    assert!(server.version().unwrap() >= 40);
    // No phone is attached to a CI runner, but listing must work and a phone that is not there
    // must be refused with adb's own reason.
    assert!(server.devices().unwrap().iter().all(|d| !d.serial.is_empty()));
    let Err(err) = server.sync("no-such-phone") else {
        panic!("a phone that is not there opened")
    };
    assert!(err.to_string().contains("not found"), "{err}");
    assert!(!err.is_connection());

    let _ = std::process::Command::new(&adb.path).arg("kill-server").output();
    let _ = std::fs::remove_dir_all(&dir);
}
