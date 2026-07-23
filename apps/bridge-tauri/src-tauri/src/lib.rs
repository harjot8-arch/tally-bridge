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
        .invoke_handler(tauri::generate_handler![
            open_external,
            detect_tally,
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
    use super::safe_external_url;

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
}
