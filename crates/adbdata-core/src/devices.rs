//! The phones adb sees (the server's `host:devices-l`, the same text as `adb devices -l`) and the
//! version of adb itself.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceState {
    /// Connected and allowed: commands work.
    Ready,
    /// The phone has not allowed this computer yet; it shows a prompt.
    Unauthorized,
    /// The phone is connected, but adb cannot talk to it (it is busy, asleep or restarting).
    Offline,
    /// The computer may not open the USB device (Linux without udev rules).
    NoPermission,
    /// In recovery, sideload or the bootloader: package commands do not work there.
    OtherMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Transport {
    Usb,
    Wifi,
    Emulator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEntry {
    pub serial: String,
    pub state: DeviceState,
    pub transport: Transport,
    /// The model as adb reports it, with underscores for spaces ("Phone_5_Plus").
    pub model: Option<String>,
    /// The device codename ("alpha").
    pub device: Option<String>,
    pub product: Option<String>,
}

impl DeviceEntry {
    /// The model with spaces, or the serial when adb gave no model (an unauthorized phone).
    pub fn display_name(&self) -> String {
        self.model
            .as_deref()
            .map(|m| m.replace('_', " "))
            .unwrap_or_else(|| self.serial.clone())
    }
}

fn state_of(word: &str) -> DeviceState {
    match word {
        "device" => DeviceState::Ready,
        "unauthorized" | "authorizing" => DeviceState::Unauthorized,
        "offline" | "connecting" => DeviceState::Offline,
        "no" => DeviceState::NoPermission, // "no permissions (...)"
        _ => DeviceState::OtherMode,       // recovery, sideload, bootloader, rescue
    }
}

fn transport_of(serial: &str) -> Transport {
    if serial.starts_with("emulator-") {
        Transport::Emulator
    } else if serial.contains("._adb-tls-connect._tcp") || is_network_address(serial) {
        Transport::Wifi
    } else {
        Transport::Usb
    }
}

/// `192.168.1.20:5555` or `[fe80::1]:5555`.
pub fn is_network_address(s: &str) -> bool {
    s.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && port.parse::<u16>().is_ok()
            && host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok()
    })
}

/// Reads `adb devices -l`. Lines adb prints while it starts its server ("* daemon ...") and the
/// header are skipped.
pub fn parse_devices(text: &str) -> Vec<DeviceEntry> {
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('*') || line.starts_with("List of devices") || line.starts_with("adb ") {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(serial), Some(state)) = (words.next(), words.next()) else {
            continue;
        };
        let mut entry = DeviceEntry {
            serial: serial.to_string(),
            state: state_of(state),
            transport: transport_of(serial),
            model: None,
            device: None,
            product: None,
        };
        for word in words {
            if let Some((key, value)) = word.split_once(':') {
                match key {
                    "model" => entry.model = Some(value.to_string()),
                    "device" => entry.device = Some(value.to_string()),
                    "product" => entry.product = Some(value.to_string()),
                    _ => {}
                }
            }
        }
        found.push(entry);
    }
    found
}

/// The version from `adb version`: the platform-tools release when it is there ("35.0.2"), else
/// the protocol version ("1.0.41").
pub fn parse_version(text: &str) -> Option<String> {
    let mut protocol = None;
    for line in text.lines().map(str::trim) {
        if let Some(v) = line.strip_prefix("Android Debug Bridge version ") {
            protocol = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version ") {
            return Some(v.split('-').next().unwrap_or(v).trim().to_string());
        }
    }
    protocol
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_every_kind_of_device_line() {
        let text = "* daemon not running; starting now at tcp:5037\n\
                    * daemon started successfully\n\
                    List of devices attached\n\
                    4b2a1c3d               device usb:1-1 product:alpha model:Phone_5_Plus device:alpha transport_id:1\n\
                    192.168.1.20:41235     device product:beta_global model:B2007X20CG device:beta transport_id:2\n\
                    adb-RF8N30ABCDE-xYz12._adb-tls-connect._tcp device product:gamma model:EX_A525F device:gamma transport_id:5\n\
                    emulator-5554          offline transport_id:3\n\
                    ZY22FLDK7V             unauthorized usb:1-2 transport_id:4\n\
                    0123456789ABCDEF       no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html] usb:3-1 transport_id:6\n\
                    R58M          recovery usb:1-3 transport_id:7\n\n";
        let d = parse_devices(text);
        assert_eq!(d.len(), 7);
        assert_eq!(d[0].serial, "4b2a1c3d");
        assert_eq!(d[0].state, DeviceState::Ready);
        assert_eq!(d[0].transport, Transport::Usb);
        assert_eq!(d[0].model.as_deref(), Some("Phone_5_Plus"));
        assert_eq!(d[0].device.as_deref(), Some("alpha"));
        assert_eq!(d[0].display_name(), "Phone 5 Plus");
        assert_eq!(d[1].transport, Transport::Wifi);
        assert_eq!(d[2].transport, Transport::Wifi);
        assert_eq!(d[3].transport, Transport::Emulator);
        assert_eq!(d[3].state, DeviceState::Offline);
        assert_eq!(d[4].state, DeviceState::Unauthorized);
        assert_eq!(d[4].display_name(), "ZY22FLDK7V");
        assert_eq!(d[5].state, DeviceState::NoPermission);
        assert_eq!(d[6].state, DeviceState::OtherMode);
    }

    #[test]
    fn no_devices_is_an_empty_list() {
        assert!(parse_devices("List of devices attached\n\n").is_empty());
        assert!(parse_devices("").is_empty());
    }

    #[test]
    fn tells_network_addresses_from_serials() {
        assert!(is_network_address("192.168.1.20:5555"));
        assert!(is_network_address("[fe80::1]:5555"));
        assert!(!is_network_address("4b2a1c3d"));
        assert!(!is_network_address("phone:99999"));
        assert!(!is_network_address("emulator-5554"));
    }

    #[test]
    fn prefers_the_platform_tools_version() {
        let text = "Android Debug Bridge version 1.0.41\nVersion 35.0.2-12147458\nInstalled as C:\\pt\\adb.exe\nRunning on Windows 10.0.26100\n";
        assert_eq!(parse_version(text).as_deref(), Some("35.0.2"));
        assert_eq!(
            parse_version("Android Debug Bridge version 1.0.39\n").as_deref(),
            Some("1.0.39")
        );
        assert_eq!(parse_version("nonsense"), None);
    }
}
