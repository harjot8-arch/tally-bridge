//! Tally Bridge — Tauri backend (Milestone 1).
//!
//! This is the Rust side of the Electron→Tauri migration. The security-critical logic
//! (crypto/protocol/core/viewmodel, and the read path) is reused TypeScript that runs UNCHANGED
//! in the WebView — exactly as `apps/web` already runs Argon2id and sealed-box unwrap in a Web
//! Worker. Rust does ONLY the Node-only I/O glue.
//!
//! What is REAL in this milestone:
//!   - `open_external`  — the shell-open allowlist, a byte-for-byte port of `main/urls.ts`
//!                        `safeExternalUrl`. This is a code-execution primitive; the allowlist is
//!                        the whole point, so it is ported exactly and unit-tested below.
//!   - `detect_tally`   — a real reachability probe against Tally's HTTP server on :9000.
//!
//! What is a LOUD STUB (returns Err, never fake data — matching this codebase's "fail loud, never
//! silently empty" rule): every stateful/crypto/sync verb. Each names the milestone that lands it.
//! A stub MUST NOT return a plausible value; a blank financial figure is recoverable, an invented
//! one is not.

use serde::Serialize;
use std::time::Duration;
use tokio::sync::Mutex;

/// Serializes every Tally request to ONE at a time. Tally's HTTP server is a single-threaded
/// desktop app the owner is actively typing into; concurrent requests hang it. This is the Rust
/// equivalent of the TS transport's single-slot queue (`packages/tally/src/transport.ts`). The
/// whole payload is <100 KB, so there is no scenario where parallelism helps.
struct TallyGate(Mutex<()>);

#[derive(Serialize)]
struct TallyResponse {
    status: u16,
    /// Raw response bytes. Decoding (UTF-16LE/BE sniff, BOM) is the audited TS codec's job in the
    /// WebView — NOT reimplemented here, so the "works on my machine, garbage on the customer's"
    /// encoding path has exactly one source of truth.
    body: Vec<u8>,
}

/// The testable core: POST raw bytes to `url`, return (status, body). No Tauri, no gate — so a
/// cargo test can exercise it directly against a fake server.
async fn perform_tally_post(
    url: &str,
    body: Vec<u8>,
    content_type: &str,
    timeout_ms: u64,
) -> Result<(u16, Vec<u8>), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        // Do not pool: a kept-alive socket into a desktop app that may restart at any moment is a
        // liability (mirrors the TS transport's `Connection: close`).
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .post(url)
        .header("Content-Type", content_type)
        .header("Connection", "close")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status().as_u16();
    let bytes = res.bytes().await.map_err(|e| e.to_string())?;
    Ok((status, bytes.to_vec()))
}

/// Byte-pipe to Tally on :9000. The WebView encodes the request (utf16le/utf8) with the reused TS
/// codec, hands us the bytes, and decodes our response bytes with the same codec — Rust only moves
/// bytes, serialized by the gate.
#[tauri::command]
async fn tally_request(
    gate: tauri::State<'_, TallyGate>,
    body: Vec<u8>,
    content_type: String,
    timeout_ms: u64,
) -> Result<TallyResponse, String> {
    let _slot = gate.0.lock().await; // single-slot: held for the whole round-trip.
    let (status, body) = perform_tally_post("http://localhost:9000", body, &content_type, timeout_ms).await?;
    Ok(TallyResponse { status, body })
}

/// The external-URL allowlist, ported verbatim from `apps/bridge/src/main/urls.ts`.
///
/// `open`ing a URL is a code-execution primitive (on Windows every registered protocol handler
/// fires), so this must agree with the TS predicate exactly. Kept as its own function so the test
/// below pins the agreement.
fn safe_external_url(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    if u.scheme() != "https" {
        return None;
    }
    // Reject embedded credentials: `https://owner:hunter2@vercel.com` would otherwise hand a real
    // host carrying secrets to the OS browser (and its history and crash reports).
    if !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    // `Url` has already IDNA/punycode-normalized the host, so a homograph arrives as `xn--…` and
    // simply misses the allowlist. Lowercase is for ASCII case only.
    let host = u.host_str()?.to_lowercase();
    const ALLOWED_HOSTS: [&str; 2] = ["vercel.com", "neon.tech"];
    const ALLOWED_SUFFIXES: [&str; 3] = [".vercel.com", ".neon.tech", ".vercel.app"];
    let allowed =
        ALLOWED_HOSTS.contains(&host.as_str()) || ALLOWED_SUFFIXES.iter().any(|s| host.ends_with(s));
    if !allowed {
        return None;
    }
    // Return the NORMALIZED href so the string that was validated is the string that gets executed
    // — handing the caller's original text to the OS after validating a parse of it is how
    // parser-differential bugs become RCE.
    Some(u.to_string())
}

#[tauri::command]
async fn open_external(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let safe = safe_external_url(&url).ok_or_else(|| "refused: URL is not on the allowlist".to_string())?;
    app.opener()
        .open_url(safe, None::<&str>)
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct TallyCompany {
    guid: String,
    name: String,
    #[serde(rename = "isActive")]
    is_active: bool,
}

#[derive(Serialize)]
struct TallyDetectResult {
    reachable: bool,
    /// A sentence for a human. Never an error code, never a stack trace.
    message: String,
    companies: Vec<TallyCompany>,
}

/// Real reachability probe. Tally's XML server lives in the interactive user session and answers
/// HTTP on :9000 only while the owner has a company open. We POST a minimal export request; ANY
/// HTTP answer means something is listening and speaking Tally's protocol, a connection refusal
/// means Tally is simply closed — the normal overnight state, NOT an error.
///
/// Company enumeration needs the TDL catalog + TSV decode from `packages/tally`, which is reused
/// TypeScript in the target architecture — so this milestone reports reachability honestly and
/// leaves `companies` empty rather than inventing names.
#[tauri::command]
async fn detect_tally() -> TallyDetectResult {
    // "List of Companies" export — enough to make Tally answer; the body is not parsed here.
    let body = "<ENVELOPE><HEADER><TALLYREQUEST>Export Data</TALLYREQUEST></HEADER><BODY><EXPORTDATA><REQUESTDESC><REPORTNAME>List of Companies</REPORTNAME></REQUESTDESC></EXPORTDATA></BODY></ENVELOPE>";
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return TallyDetectResult {
                reachable: false,
                message: format!("Could not start the Tally check ({e})."),
                companies: vec![],
            }
        }
    };
    match client
        .post("http://localhost:9000")
        .header("Content-Type", "text/xml")
        .body(body)
        .send()
        .await
    {
        Ok(_) => TallyDetectResult {
            reachable: true,
            message: "Tally is running and reachable.".to_string(),
            companies: vec![],
        },
        Err(e) if e.is_connect() => TallyDetectResult {
            reachable: false,
            message: "Tally isn't running, or no company is open. Open Tally and try again.".to_string(),
            companies: vec![],
        },
        Err(_) => TallyDetectResult {
            reachable: false,
            message: "Something is on port 9000 but it isn't answering like Tally.".to_string(),
            companies: vec![],
        },
    }
}

/// A verb not yet ported to the Rust backend. Fails LOUDLY and names its milestone. It must never
/// return a plausible-looking value — see the module header.
macro_rules! not_yet {
    ($name:ident, $milestone:literal) => {
        #[tauri::command]
        fn $name() -> Result<serde_json::Value, String> {
            Err(concat!(
                "not yet ported to the Tauri backend (",
                $milestone,
                "). This is Milestone 1: the real dashboard UI running in the Tauri shell."
            )
            .to_string())
        }
    };
}

// Fresh install: honestly not provisioned, so the renderer routes to the setup wizard. Ok(false)
// is not fake data — a first run IS unprovisioned.
#[tauri::command]
fn is_provisioned() -> bool {
    false
}

not_yet!(get_status, "Milestone 6: scheduler");
not_yet!(sync_now, "Milestone 3+5: transport + onboarding");
not_yet!(get_cards, "Milestone 2: storage + read path");
// idSK custody. CRITICAL: this crypto must run in a PRIVILEGED context, NOT the renderer WebView —
// "WebView == renderer", and the product's one non-negotiable property is that the renderer never
// holds the key that reads the data. Reusing the crypto TS "in the WebView" (as the migration plan
// first assumed) would collapse that boundary. This is the port's one genuinely unresolved design
// fork; see TAURI_MIGRATION.md.
not_yet!(unlock, "Milestone 4: keychain + idSK custody in a privileged context, NOT the WebView");
not_yet!(lock, "Milestone 4: zero the privileged-side idSK");
not_yet!(reset_dashboard, "Milestone 4");
not_yet!(rebuild_from_tally, "Milestone 2");
not_yet!(list_companies, "Milestone 3: TDL catalog + TSV decode");
not_yet!(get_mobile_access, "Milestone 5: onboarding");
not_yet!(get_wizard_state, "Milestone 5: onboarding state machine in WebView");
not_yet!(send_wizard_event, "Milestone 5");
not_yet!(recovery_qr, "Milestone 5");
not_yet!(print_recovery_sheet, "Milestone 5");

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(TallyGate(Mutex::new(())))
        .invoke_handler(tauri::generate_handler![
            open_external,
            detect_tally,
            tally_request,
            is_provisioned,
            get_status,
            sync_now,
            get_cards,
            unlock,
            lock,
            reset_dashboard,
            rebuild_from_tally,
            list_companies,
            get_mobile_access,
            get_wizard_state,
            send_wizard_event,
            recovery_qr,
            print_recovery_sheet,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::{perform_tally_post, safe_external_url};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Mutation-checkable: each case fails if the allowlist drifts from main/urls.ts.
    #[test]
    fn allowlist_matches_urls_ts() {
        // Allowed.
        assert!(safe_external_url("https://vercel.com/account/tokens").is_some());
        assert!(safe_external_url("https://neon.tech").is_some());
        assert!(safe_external_url("https://my-app.vercel.app/x").is_some());
        assert!(safe_external_url("https://sub.vercel.com").is_some());
        // Wrong scheme.
        assert!(safe_external_url("http://vercel.com").is_none());
        assert!(safe_external_url("file:///etc/passwd").is_none());
        // Credential smuggling: real host, but carrying creds.
        assert!(safe_external_url("https://owner:pw@vercel.com").is_none());
        // Userinfo host confusion: hostname is evil.com, not vercel.com.
        assert!(safe_external_url("https://vercel.com@evil.com").is_none());
        // Off the allowlist.
        assert!(safe_external_url("https://evil.com").is_none());
        assert!(safe_external_url("https://vercel.com.evil.com").is_none());
        // IDN homograph → punycode → misses the allowlist.
        assert!(safe_external_url("https://verc\u{0435}l.com").is_none());
    }

    /// Fake Tally: accept one connection, drain the request, reply with `body`.
    async fn fake_tally_once(body: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.flush().await;
            }
        });
        port
    }

    #[tokio::test]
    async fn tally_post_returns_status_and_raw_body() {
        let port = fake_tally_once(b"<ENVELOPE>ok</ENVELOPE>").await;
        let url = format!("http://127.0.0.1:{port}");
        let (status, body) = perform_tally_post(&url, b"<req/>".to_vec(), "text/xml", 2000)
            .await
            .expect("request should succeed");
        assert_eq!(status, 200);
        // Bytes are returned verbatim — decoding is the WebView codec's job, not ours.
        assert_eq!(body, b"<ENVELOPE>ok</ENVELOPE>");
    }

    #[tokio::test]
    async fn tally_post_times_out_on_a_silent_server() {
        // Accept the connection but never reply — the "Tally busy in a modal" case.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = listener.accept().await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let url = format!("http://127.0.0.1:{port}");
        let res = perform_tally_post(&url, b"<req/>".to_vec(), "text/xml", 300).await;
        assert!(res.is_err(), "a silent server must time out, got {res:?}");
    }
}
