// AuthlyX Rust SDK Version 3.0 BETA
#![allow(non_snake_case)]
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, DecodePublicKey, EncodePublicKey},
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage::ProtectedStore;
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct Error {
    pub code: String,
    pub message: String,
    pub kind: &'static str,
    pub status: u16,
    pub request_id: Option<String>,
    pub data: Value,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
fn err(code: &str, message: &str, kind: &'static str) -> Error {
    Error {
        code: code.into(),
        message: message.into(),
        kind,
        status: 0,
        request_id: None,
        data: Value::Null,
    }
}
#[derive(Clone, Deserialize)]
pub struct Response {
    pub success: bool,
    pub code: String,
    pub message: String,
    pub data: Value,
    #[serde(rename = "requestId")]
    pub request_id: String,
}
impl Response {
    pub fn ok(&self) -> bool {
        self.success
    }
    pub fn failed(&self) -> bool {
        !self.success
    }
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_value(self.data.clone()).map_err(|_| {
            err(
                "DATA_INVALID",
                "The response data could not be decoded.",
                "security",
            )
        })
    }
}
#[derive(Clone, Debug)]
pub enum Event {
    Connection(&'static str),
    SessionInvalidated(Error),
}
#[derive(Clone)]
pub struct Options {
    pub app_key: String,
    pub version: String,
    pub systemId: String,
    pub endpoint: String,
    pub response_keys: HashMap<String, String>,
    pub offline_keys: HashMap<String, String>,
    pub script_keys: HashMap<String, String>,
    pub storage: Arc<dyn ProtectedStore>,
    pub build_hash: String,
    pub request_budget: Duration,
    pub manual_heartbeat: bool,
    pub allow_local_http: bool,
    pub update_prompt: bool,
}
impl Options {
    pub fn withHeartbeat(mut self, mode: &str) -> Result<Self, Error> {
        self.manual_heartbeat = match mode {
            "server" => false,
            "manual" => true,
            _ => {
                return Err(err(
                    "CONFIG_INVALID",
                    "Use server or manual heartbeat mode.",
                    "storage",
                ))
            }
        };
        Ok(self)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Offline {
    app_id: String,
    identity_id: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    salt: String,
    #[serde(default)]
    verifier: String,
    permit: Value,
    trusted_time: i64,
    local_time: i64,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    user_data: Value,
}
struct State {
    token: Option<String>,
    session_id: String,
    app_id: String,
    identity_id: String,
    offline: Option<Offline>,
    slot: String,
    credential: Option<(String, String, String)>,
    offline_session: bool,
    anchor_server: i64,
    anchor_mono: Instant,
    anchor_wall: i64,
    deadline: i64,
    heartbeat_seconds: f64,
    jitter_seconds: f64,
    logging_out: bool,
}
impl State {
    fn anchor(&mut self, value: i64) {
        self.anchor_server = value;
        self.anchor_mono = Instant::now();
        self.anchor_wall = wall()
    }
    fn now(&self) -> i64 {
        if self.anchor_server == 0 {
            wall()
        } else {
            self.anchor_server + self.anchor_mono.elapsed().as_millis() as i64
        }
    }
}
struct Inner {
    o: Options,
    http: reqwest::Client,
    key: SigningKey,
    public_pem: String,
    key_hash: String,
    prefix: String,
    userData: StdMutex<Value>,
    state: Mutex<State>,
    life: CancellationToken,
    heartbeat: StdMutex<Option<CancellationToken>>,
    events: broadcast::Sender<Event>,
    update_offered: StdMutex<bool>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.life.cancel();
    }
}
#[derive(Clone)]
pub struct AuthlyX {
    inner: Arc<Inner>,
}
fn wall() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn hash(value: impl AsRef<[u8]>) -> String {
    Sha256::digest(value.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn slot_of(kind: &str, username: &str, license: &str) -> String {
    let id = match kind {
        "user" => username.trim().to_lowercase(),
        "license" => license.trim().to_string(),
        _ => String::new(),
    };
    hash(format!("{kind}\n{id}"))
}
fn offline_verifier(secret: &str, salt: &[u8]) -> String {
    let mut key = [0u8; 64];
    if secret.len() > 64 {
        key[..32].copy_from_slice(&Sha256::digest(secret.as_bytes()));
    } else {
        key[..secret.len()].copy_from_slice(secret.as_bytes());
    }
    let inner = Sha256::new().chain_update(key.map(|b| b ^ 0x36));
    let outer = Sha256::new().chain_update(key.map(|b| b ^ 0x5c));
    let mac = |parts: &[&[u8]]| -> [u8; 32] {
        let mut first = inner.clone();
        for part in parts {
            first.update(part);
        }
        outer.clone().chain_update(first.finalize()).finalize().into()
    };
    let mut block = mac(&[salt, &[0, 0, 0, 1]]);
    let mut out = block;
    for _ in 1..120000 {
        block = mac(&[&block]);
        for (target, value) in out.iter_mut().zip(block) {
            *target ^= value;
        }
    }
    B64.encode(out)
}
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}
#[cfg(windows)]
fn show_update((title, body, url): (String, String, String)) {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, SW_SHOWNORMAL,
    };
    let wide = |value: &str| value.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (text, caption) = (wide(&body), wide(&title));
    let flags = MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND | if url.is_empty() { MB_OK } else { MB_YESNO };
    let answer = unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), flags) };
    if answer == IDYES && !url.is_empty() {
        let (verb, target) = (wide("open"), wide(&url));
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }
}
#[cfg(not(windows))]
fn show_update(_: (String, String, String)) {}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn timestamp(value: &str) -> Result<i64, Error> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|v| v.timestamp_millis())
        .map_err(|_| {
            err(
                "RESPONSE_INVALID",
                "The server timestamp is invalid.",
                "security",
            )
        })
}
fn verify(pem: &str, payload: &str, signature: &str) -> bool {
    let Ok(key) = VerifyingKey::from_public_key_pem(pem) else {
        return false;
    };
    let Ok(bytes) = B64.decode(signature) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&bytes) else {
        return false;
    };
    key.verify(payload.as_bytes(), &sig).is_ok()
}
fn fingerprint(pem: &str) -> Option<String> {
    let k = VerifyingKey::from_public_key_pem(pem).ok()?;
    Some(hash(k.to_public_key_der().ok()?.as_bytes()))
}

pub type Client = AuthlyX;

impl AuthlyX {
    pub fn systemId() -> Result<String, Error> {
        if !cfg!(windows) {
            return Err(err(
                "SYSTEM_ID_UNAVAILABLE",
                "Supply a platform system ID through Options.",
                "storage",
            ));
        }
        let system = std::env::var("SystemRoot").map_err(|_| {
            err(
                "SYSTEM_ID_UNAVAILABLE",
                "SystemRoot is unavailable.",
                "storage",
            )
        })?;
        let output =
            std::process::Command::new(std::path::Path::new(&system).join("System32/whoami.exe"))
                .args(["/user", "/fo", "csv", "/nh"])
                .output()
                .map_err(|_| {
                    err(
                        "SYSTEM_ID_UNAVAILABLE",
                        "Could not read the Windows user SID.",
                        "storage",
                    )
                })?;
        let value = String::from_utf8_lossy(&output.stdout);
        let sid = value.split('"').find(|part| {
            part.starts_with("S-1-")
                && part
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == 'S' || c == '-')
        });
        match sid {
            Some(sid) if output.status.success() => Ok(sid.to_owned()),
            _ => Err(err(
                "SYSTEM_ID_UNAVAILABLE",
                "Could not read the Windows user SID.",
                "storage",
            )),
        }
    }

    pub fn defaults(app_key: &str, version: &str) -> Result<Options, Error> {
        let directory = std::env::var("LOCALAPPDATA").map_err(|_| {
            err(
                "STORAGE_UNAVAILABLE",
                "LOCALAPPDATA is unavailable.",
                "storage",
            )
        })?;
        Ok(Options {app_key: app_key.into(), version: version.into(), systemId: Self::systemId()?,
          endpoint: "https://api.authlyx.dev".into(), allow_local_http: true,
          storage: Arc::new(storage::WindowsProtectedStore::new(std::path::Path::new(&directory).join("AuthlyX/v3"))?),
          build_hash: String::new(), request_budget: Duration::from_secs(8), manual_heartbeat: false, update_prompt: true,
          response_keys: HashMap::from([("2318305346828e7b61e0447bfc4b3daac50dcda1b425814120ee3d6947609052".into(), "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaXXIKXRn0uPJ16wc4SX1GLArAGTAPeVhreGxp4f9/6Q=\n-----END PUBLIC KEY-----\n".into())]),
offline_keys: HashMap::from([("d3ea94e9f098eece181306689713c9f4d984c0321948fbd0007ef471bcf5b7d2".into(), "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7d2GrJ8SIUFor6bZuXo0NCX2k9SkHVz5PxOZDut3ydk=\n-----END PUBLIC KEY-----\n".into())]),
script_keys: HashMap::from([("5aec455eb0b10697".into(), "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0zpUhvFdbX95R1Q0+105MZsJr0IJ/yFTNxSiUwqfFH0=\n-----END PUBLIC KEY-----\n".into())]),
        })
    }

    pub async fn new(app_key: &str, version: &str) -> Result<Self, Error> {
        Self::withOptions(Self::defaults(app_key, version)?).await
    }

    pub async fn withOptions(mut o: Options) -> Result<Self, Error> {
        let url = url::Url::parse(&o.endpoint)
            .map_err(|_| err("CONFIG_INVALID", "Invalid API origin.", "storage"))?;
        let local = matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || (url.scheme() != "https" && !(o.allow_local_http && url.scheme() == "http" && local))
        {
            return Err(err(
                "CONFIG_INVALID",
                "Use an HTTPS API origin; HTTP is limited to explicit loopback testing.",
                "storage",
            ));
        }
        if o.app_key.is_empty()
            || o.version.is_empty()
            || o.systemId.is_empty()
            || o.response_keys.is_empty()
            || o.request_budget < Duration::from_millis(100)
            || o.request_budget > Duration::from_secs(60)
        {
            return Err(err("CONFIG_INVALID","Provide app identity, protected storage, trusted keys and a bounded request budget.","storage"));
        }
        o.endpoint = url.origin().ascii_serialization();
        let prefix = format!(
            "authlyx.v3.{}",
            hash(format!("{}/\n{}\n{}", o.endpoint, o.app_key, o.systemId))
        );
        let identity_name = format!(
            "authlyx.v3.installation.{}",
            hash(format!("{}/\n{}", o.endpoint, o.systemId))
        );
        let saved = o.storage.load(&identity_name).await?;
        let mut seed = [0u8; 32];
        if let Some(value) = saved {
            let bytes = B64.decode(value).map_err(|_| {
                err(
                    "STORAGE_INVALID",
                    "Invalid protected installation key.",
                    "storage",
                )
            })?;
            if bytes.len() != 32 {
                return Err(err(
                    "STORAGE_INVALID",
                    "Invalid protected installation key.",
                    "storage",
                ));
            };
            seed.copy_from_slice(&bytes)
        } else {
            rand::rngs::OsRng.fill_bytes(&mut seed);
            o.storage.save(&identity_name, &B64.encode(seed)).await?
        }
        let key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        let public_pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| {
                err(
                    "KEY_INVALID",
                    "Could not export installation key.",
                    "security",
                )
            })?;
        let key_hash = fingerprint(&public_pem).unwrap();
        let state = State {
            token: None,
            session_id: String::new(),
            app_id: String::new(),
            identity_id: String::new(),
            offline: None,
            slot: String::new(),
            credential: None,
            offline_session: false,
            anchor_server: 0,
            anchor_mono: Instant::now(),
            anchor_wall: 0,
            deadline: 0,
            heartbeat_seconds: 600.0,
            jitter_seconds: 15.0,
            logging_out: false,
        };
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| {
                err(
                    "CONFIG_INVALID",
                    "Could not create the HTTPS client.",
                    "network",
                )
            })?;
        let (events, _) = broadcast::channel(32);
        let client = Self {
            inner: Arc::new(Inner {
                o,
                http,
                key,
                public_pem,
                key_hash,
                prefix,
                userData: StdMutex::new(json!({})),
                state: Mutex::new(state),
                life: CancellationToken::new(),
                heartbeat: StdMutex::new(None),
                events,
                update_offered: StdMutex::new(false),
            }),
        };
        Ok(client)
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }
    fn sign(&self, payload: &str) -> String {
        B64.encode(self.inner.key.sign(payload.as_bytes()).to_bytes())
    }
    fn stop_heartbeat(&self) {
        if let Some(cancel) = self.inner.heartbeat.lock().unwrap().take() {
            cancel.cancel()
        }
    }
    fn record_name(&self, slot: &str) -> String {
        format!("{}.offline.{}", self.inner.prefix, slot)
    }
    async fn slots(&self) -> Vec<String> {
        let saved = self
            .inner
            .o
            .storage
            .load(&(self.inner.prefix.clone() + ".offline"))
            .await
            .ok()
            .flatten();
        saved
            .and_then(|value| serde_json::from_str::<Value>(&value).ok())
            .and_then(|value| value.get("slots").cloned())
            .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
            .unwrap_or_default()
    }
    async fn save_slots(&self, list: &[String]) -> Result<(), Error> {
        let name = self.inner.prefix.clone() + ".offline";
        if list.is_empty() {
            self.inner.o.storage.delete(&name).await
        } else {
            self.inner
                .o
                .storage
                .save(&name, &json!({ "slots": list }).to_string())
                .await
        }
    }
    async fn load_record(&self, slot: &str) -> Option<Offline> {
        let saved = self
            .inner
            .o
            .storage
            .load(&self.record_name(slot))
            .await
            .ok()
            .flatten()?;
        serde_json::from_str(&saved).ok()
    }
    async fn forget(&self, slot: &str) -> Result<(), Error> {
        if slot.is_empty() {
            return Ok(());
        }
        let removed = self.inner.o.storage.delete(&self.record_name(slot)).await;
        let kept: Vec<String> = self
            .slots()
            .await
            .into_iter()
            .filter(|item| item != slot)
            .collect();
        removed.and(self.save_slots(&kept).await)
    }
    async fn clear_offline(&self, s: &mut State) -> Result<(), Error> {
        s.offline = None;
        s.offline_session = false;
        let slot = s.slot.clone();
        self.forget(&slot).await
    }
    fn record_now(s: &State, record: &Offline) -> i64 {
        if s.anchor_server != 0 {
            s.now()
        } else {
            record.trusted_time + wall() - record.local_time
        }
    }
    async fn offline_login(
        &self,
        s: &mut State,
        kind: &str,
        username: &str,
        password: &str,
        license: &str,
    ) -> Result<Response, Error> {
        let name = slot_of(kind, username, license);
        let record = self.load_record(&name).await;
        let Some(record) = record.filter(|record| self.valid_record(s, record)) else {
            let _ = self.forget(&name).await;
            return Err(err(
                "OFFLINE_UNAVAILABLE",
                "Could not connect to AuthlyX, and this PC has no saved offline access for that account. Check your internet connection and try again.",
                "network",
            ));
        };
        if kind != "device" {
            let salt = B64.decode(&record.salt).unwrap_or_default();
            let secret = if kind == "user" { password } else { license };
            if !same(&offline_verifier(secret, &salt), &record.verifier) {
                return Err(if kind == "user" {
                    err("INVALID_CREDENTIALS", "Username or password is incorrect.", "server")
                } else {
                    err("LICENSE_NOT_FOUND", "License not found.", "server")
                });
            }
        }
        if s.anchor_server == 0 {
            let value = Self::record_now(s, &record);
            s.anchor(value);
        }
        s.app_id = record.app_id.clone();
        s.identity_id = record.identity_id.clone();
        s.slot = name;
        let user = if record.user_data.is_object() {
            record.user_data.clone()
        } else {
            json!({})
        };
        *self.inner.userData.lock().unwrap() = user.clone();
        s.offline = Some(record);
        s.offline_session = true;
        let _ = self.persist(s).await;
        Ok(Response {
            success: true,
            code: "OFFLINE_ACCESS".into(),
            message: "Signed in with saved offline access. Online features are unavailable until you reconnect.".into(),
            data: json!({ "offline": true, "identity": user }),
            request_id: String::new(),
        })
    }
    async fn invalidate(&self, s: &mut State, e: Error) {
        s.token = None;
        *self.inner.userData.lock().unwrap() = json!({});
        s.deadline = 0;
        self.stop_heartbeat();
        if self.clear_offline(s).await.is_err() {
            s.offline = None;
            s.offline_session = false;
        }
        let _ = self.inner.events.send(Event::SessionInvalidated(e));
    }
    fn verify_response(
        &self,
        s: &mut State,
        outer: &Value,
        status: u16,
        path: &str,
        body: &str,
        nonce: &str,
    ) -> Result<Response, Error> {
        let invalid = || {
            err(
                "RESPONSE_INVALID",
                "The server response could not be verified.",
                "security",
            )
        };
        let proof = &outer["verification"];
        let id = text(proof, "keyId");
        let pem = self.inner.o.response_keys.get(id).ok_or_else(invalid)?;
        let payload = text(proof, "signedPayload");
        if payload.len() > 2000000
            || fingerprint(pem).as_deref() != Some(id)
            || !verify(pem, payload, text(proof, "signature"))
        {
            return Err(invalid());
        }
        let signed: Value = serde_json::from_str(payload).map_err(|_| invalid())?;
        let mut envelope = outer.clone();
        envelope
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("verification");
        if signed["type"] != "authlyx.response.v3"
            || signed["keyId"] != id
            || signed["httpStatus"] != status
            || signed["request"]
                != json!({"method":"POST","path":path,"nonce":nonce,"bodySha256":hash(body)})
            || signed["response"] != envelope
        {
            return Err(invalid());
        }
        let result: Response = serde_json::from_value(envelope).map_err(|_| invalid())?;
        if result.code.is_empty() || result.request_id.is_empty() {
            return Err(invalid());
        }
        s.anchor(timestamp(text(&signed, "serverTime"))?);
        Ok(result)
    }
    async fn request(
        &self,
        s: &mut State,
        path: &str,
        data: Value,
        auth: bool,
        retry: bool,
    ) -> Result<Response, Error> {
        if self.inner.life.is_cancelled() {
            return Err(err("DISPOSED", "This client is disposed.", "cancelled"));
        }
        if auth && s.token.is_none() {
            return Err(err(
                "NOT_SIGNED_IN",
                "Sign in before using this feature.",
                "server",
            ));
        }
        let body = data.to_string();
        let until = tokio::time::Instant::now() + self.inner.o.request_budget;
        let work = async {
            for attempt in 0..3 {
                let mut bytes = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                let nonce = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                let stamp = s.now().to_string();
                let mut request = self
                    .inner
                    .http
                    .post(format!("{}{}", self.inner.o.endpoint, path))
                    .header("Content-Type", "application/json")
                    .header("X-AuthlyX-Nonce", &nonce)
                    .body(body.clone());
                if let Some(token) = s.token.as_ref().filter(|_| auth) {
                    let proof = json!({"type":"authlyx.request.v3","method":"POST","path":path,"bodySha256":hash(&body),"nonce":nonce,"timestamp":stamp,"tokenHash":hash(token)});
                    request = request
                        .bearer_auth(token)
                        .header("X-AuthlyX-Timestamp", &stamp)
                        .header("X-AuthlyX-Signature", self.sign(&proof.to_string()))
                }
                let mut delay = Duration::from_millis(150);
                let result = match request.send().await {
                    Err(_) => Err(err(
                        "NETWORK_ERROR",
                        "Could not connect to AuthlyX.",
                        "network",
                    )),
                    Ok(mut response) => {
                        let status = response.status().as_u16();
                        if let Some(after) = response
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                        {
                            delay = after
                                .parse::<u64>()
                                .ok()
                                .map(Duration::from_secs)
                                .or_else(|| {
                                    chrono::DateTime::parse_from_rfc2822(after).ok().map(|v| {
                                        Duration::from_millis(
                                            v.timestamp_millis().saturating_sub(wall()).max(0)
                                                as u64,
                                        )
                                    })
                                })
                                .unwrap_or(self.inner.o.request_budget)
                        }
                        let mut raw = Vec::new();
                        let mut read_error = false;
                        while let Some(chunk) = response.chunk().await.map_err(|_| {
                            err(
                                "NETWORK_ERROR",
                                "Could not read the server response.",
                                "network",
                            )
                        })? {
                            raw.extend_from_slice(&chunk);
                            if raw.len() > 2000000 {
                                read_error = true;
                                break;
                            }
                        }
                        if read_error {
                            Err(err(
                                "RESPONSE_INVALID",
                                "The server response is too large.",
                                "security",
                            ))
                        } else {
                            let outer = serde_json::from_slice::<Value>(&raw);
                            match outer {
                                Err(_) if status >= 500 => Err(err(
                                    "SERVICE_UNAVAILABLE",
                                    "The service is temporarily unavailable.",
                                    "network",
                                )),
                                Err(_) => Err(err(
                                    "RESPONSE_INVALID",
                                    "The server response is not valid JSON.",
                                    "security",
                                )),
                                Ok(value)
                                    if value.get("verification").is_none() && status >= 500 =>
                                {
                                    Err(err(
                                        "SERVICE_UNAVAILABLE",
                                        "The service is temporarily unavailable.",
                                        "network",
                                    ))
                                }
                                Ok(value) => self
                                    .verify_response(s, &value, status, path, &body, &nonce)
                                    .and_then(|r| {
                                        if status >= 400 || !r.success {
                                            Err(Error {
                                                code: r.code,
                                                message: r.message,
                                                kind: if status == 429 || status >= 500 {
                                                    "network"
                                                } else {
                                                    "server"
                                                },
                                                status,
                                                request_id: Some(r.request_id),
                                                data: r.data,
                                            })
                                        } else {
                                            Ok(r)
                                        }
                                    }),
                            }
                        }
                    }
                };
                match result {
                    Ok(value) => {
                        let _ = self.inner.events.send(Event::Connection("online"));
                        return Ok(value);
                    }
                    Err(e) => {
                        if retry
                            && attempt < 2
                            && (e.kind == "network" || e.code == "REQUEST_TIME_INVALID")
                            && tokio::time::Instant::now() + delay + Duration::from_millis(50)
                                < until
                        {
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return Err(e);
                    }
                }
            }
            Err(err(
                "NETWORK_ERROR",
                "Could not connect to AuthlyX.",
                "network",
            ))
        };
        let result = tokio::select! {_ = self.inner.life.cancelled()=>Err(err("REQUEST_CANCELLED","The request was cancelled.","cancelled")),value=tokio::time::timeout_at(until,work)=>value.unwrap_or_else(|_|Err(err("NETWORK_TIMEOUT","The request timed out. Try again when connected.","network")))};
        if let Err(e) = &result {
            if e.kind == "security" {
                let _ = self.inner.events.send(Event::Connection("untrusted"));
                self.invalidate(s, e.clone()).await
            } else if e.kind == "network" {
                let _ = self.inner.events.send(Event::Connection("disconnected"));
            } else if auth
                && matches!(
                    e.code.as_str(),
                    "SESSION_EXPIRED"
                        | "ACCESS_REVOKED"
                        | "APP_PAUSED"
                        | "ACCESS_EXPIRED"
                        | "ACCESS_DENIED"
                        | "IP_BLACKLISTED"
                        | "IP_NOT_WHITELISTED"
                        | "SID_BLACKLISTED"
                        | "SID_NOT_WHITELISTED"
                        | "VERSION_NOT_ALLOWED"
                        | "HASH_NOT_ALLOWED"
                        | "COUNTRY_BLOCKED"
                        | "VPN_NOT_ALLOWED"
                        | "DEVICE_NOT_ALLOWED"
                        | "APP_DISABLED"
                        | "IP_BLOCKED"
                        | "SID_BLOCKED"
                        | "UPDATE_REQUIRED"
                        | "VERSION_MISMATCH"
                        | "INVALID_HASH"
                        | "VPN_BLOCKED"
                        | "USER_BANNED"
                        | "USER_SUSPENDED"
                        | "USER_EXPIRED"
                        | "LICENSE_BANNED"
                        | "LICENSE_PAUSED"
                        | "LICENSE_EXPIRED"
                        | "MOTHERBOARD_BANNED"
                        | "MOTHERBOARD_PAUSED"
                        | "MOTHERBOARD_EXPIRED"
                        | "PROCESSOR_BANNED"
                        | "PROCESSOR_PAUSED"
                        | "PROCESSOR_EXPIRED"
                )
            {
                self.invalidate(s, e.clone()).await
            }
        }
        result
    }
    pub async fn initialize(&self) -> Result<Response, Error> {
        self.init().await
    }
    pub fn initializeWith<F>(&self, completed: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(Result<Response, Error>) + Send + 'static,
    {
        self.initWith(completed)
    }
    pub async fn init(&self) -> Result<Response, Error> {
        let mut s = self.inner.state.lock().await;
        let result = self
            .request(
                &mut s,
                "/v3/initialize",
                json!({"appKey":self.inner.o.app_key,"version":self.inner.o.version}),
                false,
                true,
            )
            .await;
        drop(s);
        let error = match result {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };
        if error.kind == "network" {
            if self.hasOfflineAccess().await {
                return Ok(Response {
                    success: true,
                    code: "OFFLINE_MODE".into(),
                    message: "You are offline. Sign in with the account you saved offline access for.".into(),
                    data: json!({}),
                    request_id: String::new(),
                });
            }
            return Ok(Response {
                success: false,
                code: error.code,
                message: "Could not connect to AuthlyX. Check your internet connection.".into(),
                data: Value::Null,
                request_id: error.request_id.unwrap_or_default(),
            });
        }
        if error.kind != "server" {
            return Err(error);
        }
        if let Some(prompt) = self.update_prompt(&error.data, &error.code, &error.message) {
            let _ = tokio::task::spawn_blocking(move || show_update(prompt)).await;
        }
        Ok(Response {
            success: false,
            code: error.code,
            message: error.message,
            data: error.data,
            request_id: error.request_id.unwrap_or_default(),
        })
    }
    fn update_prompt(&self, data: &Value, code: &str, message: &str) -> Option<(String, String, String)> {
        if !self.inner.o.update_prompt || !cfg!(windows) {
            return None;
        }
        let update = data.get("update").filter(|v| v.is_object())?;
        let mut url = text(update, "url").to_string();
        if !url.starts_with("https://") && !url.starts_with("http://") {
            url.clear();
        }
        let required = code == "UPDATE_REQUIRED" || code == "VERSION_MISMATCH";
        if !required {
            let mut offered = self.inner.update_offered.lock().unwrap();
            if *offered || data.get("updateAvailable") != Some(&Value::Bool(true)) || url.is_empty() {
                return None;
            }
            *offered = true;
        }
        let (latest, notes) = (text(update, "version"), text(update, "notes"));
        let mut body = if required { message.to_string() } else { format!("Version {latest} is available.") };
        body += &format!("\n\nYour version: {}", self.inner.o.version);
        if !latest.is_empty() {
            body += &format!("\nLatest version: {latest}");
        }
        if !notes.is_empty() {
            body += &format!("\n\n{notes}");
        }
        if !url.is_empty() {
            body += "\n\nOpen the download page?";
        }
        let title = match code {
            "UPDATE_REQUIRED" => "Update required",
            "VERSION_MISMATCH" => "Version not supported",
            _ => "Update available",
        };
        Some((title.to_string(), body, url))
    }
    pub fn userData(&self) -> Value {
        self.inner.userData.lock().unwrap().clone()
    }
    pub async fn registerUser(
        &self,
        username: &str,
        password: &str,
        license_key: &str,
    ) -> Result<Response, Error> {
        self.login_impl("register", username, password, license_key)
            .await
    }
    pub async fn changePassword(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<Response, Error> {
        self.protected(
            "/v3/account/password",
            json!({"currentPassword":current_password,"newPassword":new_password}),
            false,
        )
        .await
    }
    pub async fn redeemLicense(&self, license_key: &str) -> Result<Response, Error> {
        self.protected(
            "/v3/licenses/redeem",
            json!({"licenseKey":license_key}),
            false,
        )
        .await
    }
    pub async fn log(&self, message: &str) -> Result<Response, Error> {
        self.protected("/v3/logs/add", json!({"message":message}), false)
            .await
    }
    pub async fn login(&self, username: &str, password: &str) -> Result<Response, Error> {
        self.login_impl("user", username, password, "").await
    }
    pub async fn licenseLogin(&self, license: &str) -> Result<Response, Error> {
        self.login_impl("license", "", "", license).await
    }
    pub async fn deviceLogin(&self) -> Result<Response, Error> {
        self.login_impl("device", "", "", "").await
    }
    async fn login_impl(
        &self,
        kind: &str,
        username: &str,
        password: &str,
        license: &str,
    ) -> Result<Response, Error> {
        let mut s = self.inner.state.lock().await;
        if s.token.is_some() || s.offline_session {
            return Err(err(
                "ALREADY_SIGNED_IN",
                "Sign out before starting another session.",
                "server",
            ));
        }
        s.logging_out = false;
        let challenge = match self.request(&mut s,"/v3/challenge",json!({"appKey":self.inner.o.app_key,"installationPublicKey":self.inner.public_pem}),false,false).await {
            Ok(value) => value.data,
            Err(e) if e.kind == "network" && kind != "register" => {
                return self.offline_login(&mut s, kind, username, password, license).await
            }
            Err(e) => return Err(e),
        };
        let operation = json!({"type":kind,"appKey":self.inner.o.app_key,"version":self.inner.o.version,"sid":self.inner.o.systemId,"hash":self.inner.o.build_hash,"username":username,"password":password,"licenseKey":license,"device":device_details()});
        let signature =
            self.sign(&json!({"challenge":challenge["payload"],"operation":operation}).to_string());
        let mut body = operation;
        body["challengeId"] = challenge["challengeId"].clone();
        body["signature"] = signature.into();
        let mut result = self
            .request(&mut s, "/v3/login", body, false, false)
            .await?;
        s.app_id = text(
            &serde_json::from_str::<Value>(text(&challenge, "payload"))
                .map_err(|_| err("RESPONSE_INVALID", "Invalid challenge.", "security"))?,
            "appId",
        )
        .into();
        let mut identity = result.data["identity"].clone();
        for (dest, src) in [
            ("SID", "systemId"),
            ("Email", "email"),
            ("Plan", "plan"),
            ("ExpiryDate", "expiry"),
            ("Country", "country"),
            ("IpAddress", "ipAddress"),
            ("DeviceLimit", "deviceLimit"),
            ("LicenseKey", "licenseKey"),
        ] {
            identity[dest] = identity[src].clone();
        }
        identity["Username"] = if identity["type"] == "user" {
            identity["name"].clone()
        } else {
            json!("")
        };
        *self.inner.userData.lock().unwrap() = identity;
        s.identity_id = text(&result.data, "identityId").into();
        s.session_id = text(&result.data, "sessionId").into();
        s.token = Some(text(&result.data, "token").into());
        let offline_kind = if kind == "register" { "user" } else { kind };
        s.slot = slot_of(offline_kind, username, license);
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let verifier = match offline_kind {
            "user" => offline_verifier(password, &salt),
            "license" => offline_verifier(license, &salt),
            _ => String::new(),
        };
        s.credential = Some((offline_kind.to_string(), B64.encode(salt), verifier));
        self.lease(&mut s, &result.data).await?;
        result.data.as_object_mut().unwrap().remove("token");
        drop(s);
        self.start_heartbeat();
        if let Some(prompt) = self.update_prompt(&result.data, &result.code, &result.message) {
            std::thread::spawn(move || show_update(prompt));
        }
        Ok(result)
    }
    async fn lease(&self, s: &mut State, data: &Value) -> Result<(), Error> {
        let deadline = timestamp(text(data, "accessDeadline")).unwrap_or(0);
        if deadline <= 0 || deadline > s.now() + 7200100 {
            let error = err(
                "LEASE_INVALID",
                "The session deadline is invalid.",
                "security",
            );
            self.invalidate(s, error.clone()).await;
            return Err(error);
        }
        s.deadline = deadline;
        {
            let mut identity = self.inner.userData.lock().unwrap();
            for key in ["features", "featureValues", "metadata"] {
                if let Some(value) = data.get(key) {
                    identity[key] = value.clone();
                }
            }
        }
        s.heartbeat_seconds = data["heartbeatSeconds"]
            .as_f64()
            .unwrap_or(600.0)
            .clamp(1.0, 3600.0);
        s.jitter_seconds = data["jitterSeconds"]
            .as_f64()
            .unwrap_or(15.0)
            .clamp(0.0, 15.0);
        Ok(())
    }
    pub async fn checkSession(&self) -> Result<Response, Error> {
        let mut s = self.inner.state.lock().await;
        let result = self
            .request(&mut s, "/v3/session/check", json!({}), true, true)
            .await?;
        self.lease(&mut s, &result.data).await?;
        Ok(result)
    }
    async fn protected(&self, path: &str, data: Value, retry: bool) -> Result<Response, Error> {
        let mut s = self.inner.state.lock().await;
        if s.token.is_some() && s.now() >= s.deadline {
            let r = self
                .request(&mut s, "/v3/session/check", json!({}), true, true)
                .await?;
            self.lease(&mut s, &r.data).await?
        }
        self.request(&mut s, path, data, true, retry).await
    }
    pub fn initWith<F>(&self, completed: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(Result<Response, Error>) + Send + 'static,
    {
        let client = self.clone();
        tokio::spawn(async move {
            completed(client.init().await);
        })
    }
    pub fn licenseLoginWith<F>(&self, key: String, completed: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(Result<Response, Error>) + Send + 'static,
    {
        let client = self.clone();
        tokio::spawn(async move {
            completed(client.licenseLogin(&key).await);
        })
    }
    pub fn getVariableWith<F>(&self, name: String, completed: F) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(Result<Response, Error>) + Send + 'static,
    {
        let client = self.clone();
        tokio::spawn(async move {
            completed(client.getVariable(&name).await);
        })
    }
    pub fn getScriptWith<F>(
        &self,
        name: String,
        revision: Option<u64>,
        completed: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnOnce(Result<Response, Error>) + Send + 'static,
    {
        let client = self.clone();
        tokio::spawn(async move {
            completed(client.getScript(&name, revision).await);
        })
    }
    pub async fn getMetadata(&self) -> Result<Response, Error> {
        self.protected("/v3/metadata/get", json!({}), true).await
    }
    pub async fn updateVariable(&self, name: &str, value: &str) -> Result<Response, Error> {
        self.protected("/v3/data/set", json!({"name":name,"value":value}), false)
            .await
    }
    pub async fn getFeatures(&self) -> Result<Response, Error> {
        self.protected("/v3/features/list", json!({}), true).await
    }
    pub async fn getFeature(&self, name: &str) -> Result<Response, Error> {
        self.protected("/v3/features/get", json!({"name":name}), true)
            .await
    }
    pub async fn getAllMetadata(&self) -> Result<Response, Error> {
        self.protected("/v3/metadata/list", json!({}), true).await
    }
    pub async fn getMetadataValue(&self, key: &str) -> Result<Response, Error> {
        self.protected("/v3/metadata/get", json!({"key":key}), true)
            .await
    }
    pub async fn checkMetadata(&self, key: &str) -> Result<Response, Error> {
        self.protected("/v3/metadata/check", json!({"key":key}), true)
            .await
    }
    pub async fn sendWebhook(&self, name: &str, data: Value) -> Result<Response, Error> {
        self.protected(
            "/v3/webhooks/send",
            json!({"event":name,"data":data}),
            false,
        )
        .await
    }
    pub async fn setMetadata(&self, key: &str, value: Value) -> Result<Response, Error> {
        self.protected("/v3/metadata/set", json!({"key":key,"value":value}), false)
            .await
    }
    pub async fn checkFeature(&self, name: &str) -> Result<Response, Error> {
        self.protected("/v3/features/check", json!({"name":name}), true)
            .await
    }
    pub async fn getVariable(&self, name: &str) -> Result<Response, Error> {
        self.protected("/v3/data/get", json!({"name":name}), true)
            .await
    }
    pub async fn getScript(&self, name: &str, revision: Option<u64>) -> Result<Response, Error> {
        let mut data = json!({"name":name});
        if let Some(v) = revision {
            data["revision"] = v.into()
        }
        let result = self.protected("/v3/scripts/get", data, true).await?;
        let s = self.inner.state.lock().await;
        let payload = text(&result.data, "signedPayload");
        let manifest: Value = serde_json::from_str(payload).map_err(|_| {
            err(
                "SCRIPT_INVALID",
                "The script could not be verified.",
                "security",
            )
        })?;
        if manifest.get("issuedAt").is_some() || manifest.get("expiresAt").is_some() {
            let issued = manifest["issuedAt"].as_i64().unwrap_or(0);
            let expires = manifest["expiresAt"].as_i64().unwrap_or(0);
            if issued <= 0 || issued > s.now() + 30000 || expires <= s.now() || expires <= issued {
                return Err(err(
                    "SCRIPT_INVALID",
                    "The script could not be verified.",
                    "security",
                ));
            }
        }
        if let Some(minimum) = manifest.get("minimumRevision") {
            if minimum.as_u64().unwrap_or(0) == 0
                || manifest["revision"].as_u64().unwrap_or(0) < minimum.as_u64().unwrap_or(0)
            {
                return Err(err(
                    "SCRIPT_INVALID",
                    "The script could not be verified.",
                    "security",
                ));
            }
        }
        let content = text(&result.data, "content");
        let valid = self
            .inner
            .o
            .script_keys
            .get(text(&manifest, "keyId"))
            .map(|k| verify(k, payload, text(&result.data, "signature")))
            .unwrap_or(false)
            && manifest == result.data["manifest"]
            && manifest["appId"] == s.app_id
            && manifest["name"] == name
            && revision.map(|v| manifest["revision"] == v).unwrap_or(true)
            && manifest["sha256"] == hash(content)
            && manifest["bytes"] == content.len();
        if !valid {
            return Err(err(
                "SCRIPT_INVALID",
                "The script could not be verified.",
                "security",
            ));
        }
        Ok(result)
    }
    pub async fn saveOfflineAccess(&self) -> Result<Response, Error> {
        let mut s = self.inner.state.lock().await;
        if s.token.is_none() || s.credential.is_none() {
            return Err(err(
                "NOT_SIGNED_IN",
                "Sign in online before saving offline access.",
                "server",
            ));
        }
        let challenge = self
            .request(&mut s, "/v3/offline/challenge", json!({}), true, false)
            .await?
            .data;
        let signature=self.sign(&json!({"challenge":challenge["payload"],"operation":{"action":"offlinePermit","sessionId":s.session_id}}).to_string());
        let r = self
            .request(
                &mut s,
                "/v3/offline/permit",
                json!({"challengeId":challenge["challengeId"],"signature":signature}),
                true,
                false,
            )
            .await?;
        let (kind, salt, verifier) = s.credential.clone().unwrap_or_default();
        let record = Offline {
            app_id: s.app_id.clone(),
            identity_id: s.identity_id.clone(),
            kind,
            salt,
            verifier,
            permit: r.data.clone(),
            trusted_time: s.now(),
            local_time: wall(),
            user_data: self.inner.userData.lock().unwrap().clone(),
        };
        if !self.valid_record(&s, &record) {
            return Err(err(
                "OFFLINE_INVALID",
                "The offline permit could not be verified.",
                "security",
            ));
        }
        let saved = self
            .inner
            .o
            .storage
            .save(&self.record_name(&s.slot), &serde_json::to_string(&record).unwrap())
            .await;
        let mut list = self.slots().await;
        if !list.contains(&s.slot) {
            list.push(s.slot.clone());
        }
        if saved.and(self.save_slots(&list).await).is_err() {
            return Err(err(
                "STORAGE_INVALID",
                "Could not save protected offline state.",
                "storage",
            ));
        }
        Ok(r)
    }
    fn valid_offline(&self, s: &State) -> bool {
        s.offline_session && s.offline.as_ref().is_some_and(|record| self.valid_record(s, record))
    }
    fn valid_record(&self, s: &State, offline: &Offline) -> bool {
        if s.logging_out
            || self.inner.life.is_cancelled()
            || wall() < s.anchor_wall
            || wall() < offline.local_time
        {
            return false;
        }
        let payload = text(&offline.permit, "signedPayload");
        if payload.len() > 4096 {
            return false;
        }
        let Ok(claims) = serde_json::from_str::<Value>(payload) else {
            return false;
        };
        let id = text(&claims, "keyId");
        let Some(key) = self.inner.o.offline_keys.get(id) else {
            return false;
        };
        let issued = claims["issuedAt"].as_i64().unwrap_or(i64::MAX);
        let expires = claims["expiresAt"].as_i64().unwrap_or(i64::MIN);
        let now = Self::record_now(s, offline);
        fingerprint(key).as_deref() == Some(id)
            && verify(key, payload, text(&offline.permit, "signature"))
            && claims["type"] == "authlyx.offline.v1"
            && claims["appId"] == offline.app_id
            && claims["subjectId"] == offline.identity_id
            && claims["installationKeyHash"] == self.inner.key_hash
            && issued <= now
            && now < expires
            && expires > issued
            && expires.saturating_sub(issued) <= 2592000000
            && now >= offline.trusted_time
    }
    async fn persist(&self, s: &mut State) -> Result<(), Error> {
        let now = match s.offline.as_ref() {
            Some(record) => Self::record_now(s, record),
            None => return Ok(()),
        };
        let name = self.record_name(&s.slot);
        if let Some(offline) = s.offline.as_mut() {
            offline.trusted_time = now;
            offline.local_time = wall();
            self.inner
                .o
                .storage
                .save(&name, &serde_json::to_string(offline).unwrap())
                .await?
        }
        Ok(())
    }
    pub async fn hasOfflineAccess(&self) -> bool {
        let mut s = self.inner.state.lock().await;
        if !s.offline_session {
            for slot in self.slots().await {
                if let Some(record) = self.load_record(&slot).await {
                    if self.valid_record(&s, &record) {
                        return true;
                    }
                }
            }
            return false;
        }
        if !self.valid_offline(&s) {
            return false;
        }
        if self.persist(&mut s).await.is_err() {
            s.offline = None;
            return false;
        }
        true
    }
    pub async fn hasAccess(&self) -> bool {
        let mut s = self.inner.state.lock().await;
        if s.logging_out || self.inner.life.is_cancelled() {
            return false;
        }
        if s.token.is_some() && s.deadline > s.now() {
            return true;
        }
        if !self.valid_offline(&s) {
            return false;
        }
        if self.persist(&mut s).await.is_err() {
            s.offline = None;
            return false;
        }
        true
    }
    pub async fn logout(&self) -> Result<(), Error> {
        let client = self.clone();
        tokio::spawn(async move { client.logout_inner().await })
            .await
            .map_err(|_| {
                err(
                    "LOGOUT_FAILED",
                    "Logout cleanup could not finish.",
                    "storage",
                )
            })?
    }
    async fn logout_inner(&self) -> Result<(), Error> {
        let mut s = self.inner.state.lock().await;
        s.logging_out = true;
        self.stop_heartbeat();
        let result = if s.token.is_some() {
            self.request(&mut s, "/v3/session/logout", json!({}), true, false)
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        s.token = None;
        *self.inner.userData.lock().unwrap() = json!({});
        s.deadline = 0;
        let clear = self.clear_offline(&mut s).await;
        s.credential = None;
        s.slot.clear();
        result.and(clear)
    }
    fn start_heartbeat(&self) {
        self.stop_heartbeat();
        if self.inner.o.manual_heartbeat {
            return;
        }
        let cancel = self.inner.life.child_token();
        *self.inner.heartbeat.lock().unwrap() = Some(cancel.clone());
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else { return };
                let client = AuthlyX { inner };
                let duration = {
                    let s = client.inner.state.lock().await;
                    if s.token.is_none() || s.logging_out {
                        return;
                    }
                    Duration::from_secs_f64(
                        (s.heartbeat_seconds
                            + (rand::random::<f64>() * 2.0 - 1.0) * s.jitter_seconds)
                            .max(1.0),
                    )
                };
                drop(client);
                tokio::select! {_ = cancel.cancelled()=>return,_ = tokio::time::sleep(duration)=>{}}
                let Some(inner) = weak.upgrade() else { return };
                let client = AuthlyX { inner };
                let _ = client.checkSession().await;
                drop(client);
            }
        });
    }
    pub async fn onResume(&self) -> Result<Response, Error> {
        self.checkSession().await
    }
    pub async fn close(&self) {
        self.inner.life.cancel();
        self.stop_heartbeat();
        let mut s = self.inner.state.lock().await;
        s.token = None;
        *self.inner.userData.lock().unwrap() = json!({});
        s.deadline = 0;
    }
}

pub mod storage {
    use crate::{err, hash, Error};
    use async_trait::async_trait;
    use std::{collections::HashMap, path::PathBuf};
    use tokio::sync::Mutex;
    #[async_trait]
    pub trait ProtectedStore: Send + Sync {
        async fn load(&self, name: &str) -> Result<Option<String>, Error>;
        async fn save(&self, name: &str, value: &str) -> Result<(), Error>;
        async fn delete(&self, name: &str) -> Result<(), Error>;
    }
    #[derive(Default)]
    pub struct MemoryStore {
        values: Mutex<HashMap<String, String>>,
    }
    #[async_trait]
    impl ProtectedStore for MemoryStore {
        async fn load(&self, name: &str) -> Result<Option<String>, Error> {
            Ok(self.values.lock().await.get(name).cloned())
        }
        async fn save(&self, name: &str, value: &str) -> Result<(), Error> {
            self.values.lock().await.insert(name.into(), value.into());
            Ok(())
        }
        async fn delete(&self, name: &str) -> Result<(), Error> {
            self.values.lock().await.remove(name);
            Ok(())
        }
    }
    pub struct WindowsProtectedStore {
        directory: PathBuf,
    }
    impl WindowsProtectedStore {
        pub fn new(directory: PathBuf) -> Result<Self, Error> {
            if !cfg!(windows) {
                return Err(err(
                    "STORAGE_UNAVAILABLE",
                    "Supply a platform-protected store.",
                    "storage",
                ));
            }
            std::fs::create_dir_all(&directory).map_err(|_| {
                err(
                    "STORAGE_INVALID",
                    "Could not create protected storage.",
                    "storage",
                )
            })?;
            Ok(Self { directory })
        }
        fn file(&self, name: &str) -> PathBuf {
            self.directory.join(hash(name) + ".dat")
        }
    }
    #[cfg(windows)]
    fn crypt(name: &str, value: &[u8], protect: bool) -> Result<Vec<u8>, Error> {
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB},
        };
        let mut source = CRYPT_INTEGER_BLOB {
            cbData: value.len() as u32,
            pbData: value.as_ptr() as *mut u8,
        };
        let mut entropy = CRYPT_INTEGER_BLOB {
            cbData: name.len() as u32,
            pbData: name.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let result = unsafe {
            if protect {
                CryptProtectData(
                    &mut source,
                    std::ptr::null(),
                    &mut entropy,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    1,
                    &mut output,
                )
            } else {
                CryptUnprotectData(
                    &mut source,
                    std::ptr::null_mut(),
                    &mut entropy,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    1,
                    &mut output,
                )
            }
        };
        if result == 0 {
            return Err(err(
                "STORAGE_INVALID",
                "Protected state could not be read or saved.",
                "storage",
            ));
        }
        let bytes = unsafe {
            let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            LocalFree(output.pbData as *mut _);
            bytes
        };
        Ok(bytes)
    }
    #[cfg(not(windows))]
    fn crypt(_: &str, _: &[u8], _: bool) -> Result<Vec<u8>, Error> {
        Err(err(
            "STORAGE_UNAVAILABLE",
            "Supply a platform-protected store.",
            "storage",
        ))
    }
    #[async_trait]
    impl ProtectedStore for WindowsProtectedStore {
        async fn load(&self, name: &str) -> Result<Option<String>, Error> {
            let file = self.file(name);
            let bytes = match std::fs::read(file) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => {
                    return Err(err(
                        "STORAGE_INVALID",
                        "Could not read protected state.",
                        "storage",
                    ))
                }
            };
            if bytes.len() > 1048576 {
                return Err(err(
                    "STORAGE_INVALID",
                    "Protected state is too large.",
                    "storage",
                ));
            }
            String::from_utf8(crypt(name, &bytes, false)?)
                .map(Some)
                .map_err(|_| err("STORAGE_INVALID", "Protected state is invalid.", "storage"))
        }
        async fn save(&self, name: &str, value: &str) -> Result<(), Error> {
            use std::io::Write;
            let file = self.file(name);
            let temp = file.with_extension(format!("{}.tmp", rand::random::<u64>()));
            let result = (|| {
                let mut stream = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&temp)?;
                stream.write_all(
                    &crypt(name, value.as_bytes(), true).map_err(std::io::Error::other)?,
                )?;
                stream.sync_all()?;
                drop(stream);
                std::fs::rename(&temp, &file)
            })();
            let _ = std::fs::remove_file(&temp);
            result.map_err(|_: std::io::Error| {
                err(
                    "STORAGE_INVALID",
                    "Could not save protected state.",
                    "storage",
                )
            })
        }
        async fn delete(&self, name: &str) -> Result<(), Error> {
            match std::fs::remove_file(self.file(name)) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(err(
                    "STORAGE_INVALID",
                    "Could not remove protected state.",
                    "storage",
                )),
            }
        }
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetSystemFirmwareTable(provider: u32, id: u32, buffer: *mut u8, size: u32) -> u32;
}

fn device_text(value: &str) -> String {
    let text: String = value
        .chars()
        .filter(|c| (' '..='~').contains(c) && !matches!(c, '"' | '<' | '>' | '&') && *c as u32 != 92)
        .collect();
    text.trim().chars().take(100).collect()
}

fn chassis_type(chassis: u8) -> &'static str {
    match chassis {
        8 | 9 | 10 | 14 | 31 | 32 => "Windows laptop",
        30 => "Windows tablet",
        17 | 23 | 28 | 29 => "Windows server",
        3 | 4 | 5 | 6 | 7 | 13 | 15 | 16 | 24 | 35 | 36 => "Windows desktop",
        _ => "Windows",
    }
}

#[cfg(windows)]
fn read_firmware() -> (String, String, String) {
    let (mut kind, mut baseboard, mut uuid) = ("Windows".to_string(), String::new(), String::new());
    let size = unsafe { GetSystemFirmwareTable(0x52534D42, 0, std::ptr::null_mut(), 0) };
    if size <= 8 {
        return (kind, baseboard, uuid);
    }
    let mut raw = vec![0u8; size as usize];
    if unsafe { GetSystemFirmwareTable(0x52534D42, 0, raw.as_mut_ptr(), size) } != size {
        return (kind, baseboard, uuid);
    }
    let end = (8 + u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize).min(raw.len());
    let mut p = 8;
    while p + 4 <= end {
        let (table, header) = (raw[p], raw[p + 1] as usize);
        if header < 4 || p + header > end {
            break;
        }
        let mut strings_end = p + header;
        while strings_end + 1 < end && !(raw[strings_end] == 0 && raw[strings_end + 1] == 0) {
            strings_end += 1;
        }
        let parts: Vec<String> = raw[p + header..strings_end]
            .split(|b| *b == 0)
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        let text_at = |index: u8| -> String {
            if index == 0 { String::new() } else { parts.get(index as usize - 1).cloned().unwrap_or_default() }
        };
        if table == 1 && header >= 0x18 {
            let u = &raw[p + 8..p + 24];
            uuid = format!(
                "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
            );
        } else if table == 2 && header >= 8 && baseboard.is_empty() {
            baseboard = text_at(raw[p + 7]);
        } else if table == 3 && header >= 6 && kind == "Windows" {
            kind = chassis_type(raw[p + 5] & 0x7F).to_string();
        }
        p = strings_end + 2;
        if table == 127 {
            break;
        }
    }
    (kind, baseboard, uuid)
}

#[cfg(not(windows))]
fn read_firmware() -> (String, String, String) {
    (String::new(), String::new(), String::new())
}

fn device_details() -> Value {
    let name = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_default();
    let (kind, baseboard, uuid) = read_firmware();
    json!({"name": device_text(&name), "type": kind, "baseboard": device_text(&baseboard), "uuid": device_text(&uuid)})
}
