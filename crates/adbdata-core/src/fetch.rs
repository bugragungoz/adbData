//! Downloads: the community package list and platform-tools.

use std::io::Read;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("the download failed: {0}")]
    Http(String),
    #[error("the download is larger than {0} MB")]
    TooLarge(u64),
}

/// Downloads `url` into memory, at most `max` bytes, telling `progress` the bytes so far and the
/// total when the server says it.
pub fn fetch(url: &str, max: u64, progress: &mut dyn FnMut(u64, Option<u64>)) -> Result<Vec<u8>, FetchError> {
    // The system's own TLS and certificate store (SChannel on Windows), so a proxy or antivirus
    // certificate the computer trusts is trusted here too. The roots must be named: ureq's default
    // swaps the store for a bundled list, and SChannel then rejects a chain that Windows builds to
    // a root of its own (dl.google.com does).
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::NativeTls)
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .user_agent(concat!("adbData/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let response = agent.get(url).call().map_err(|e| FetchError::Http(e.to_string()))?;
    let total = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if total.is_some_and(|t| t > max) {
        return Err(FetchError::TooLarge(max / 1_000_000));
    }
    let mut reader = response.into_body().into_with_config().limit(max + 1).reader();
    let mut bytes = Vec::with_capacity(total.unwrap_or(0) as usize);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk).map_err(|e| FetchError::Http(e.to_string()))?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() as u64 > max {
            return Err(FetchError::TooLarge(max / 1_000_000));
        }
        progress(bytes.len() as u64, total);
    }
    Ok(bytes)
}
