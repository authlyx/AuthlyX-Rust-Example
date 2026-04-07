use rand::RngCore;
use reqwest::blocking::Client;
use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE, USER_AGENT};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct Response {
    pub success: bool,
    pub message: String,
    pub raw: String,
    pub code: String,
    pub status_code: u16,
    pub request_id: String,
    pub nonce: String,
    pub signature_kid: String,
}

#[derive(Clone, Default)]
pub struct UserData {
    pub username: String,
    pub email: String,
    pub license_key: String,
    pub subscription: String,
    pub subscription_level: String,
    pub expiry_date: String,
    pub days_left: i64,
    pub last_login: String,
    pub hwid: String,
    pub ip_address: String,
    pub registered_at: String,
}

#[derive(Clone, Default)]
pub struct VariableData {
    pub var_key: String,
    pub var_value: String,
    pub updated_at: String,
}

#[derive(Clone, Default)]
pub struct UpdateData {
    pub available: bool,
    pub latest_version: String,
    pub download_url: String,
    pub force_update: bool,
    pub changelog: String,
    pub show_reminder: bool,
    pub reminder_message: String,
    pub allowed_until: String,
}

pub struct AuthlyX {
    pub owner_id: String,
    pub app_name: String,
    pub version: String,
    pub secret: String,
    pub base_url: String,
    pub debug: bool,

    pub session_id: String,
    pub initialized: bool,
    pub application_hash: String,

    cached_ip: String,
    cached_ip_expires_at_ms: i64,

    pub response: Response,
    pub user_data: UserData,
    pub variable_data: VariableData,
    pub update_data: UpdateData,

    http: Client,
}

impl AuthlyX {
    pub fn new(owner_id: &str, app_name: &str, version: &str, secret: &str, debug: bool, api: Option<&str>) -> Self {
        let base = api
            .unwrap_or("https://authly.cc/api/v2")
            .trim()
            .trim_end_matches('/')
            .to_string();

        let http = Client::builder().timeout(Duration::from_secs(30)).build().unwrap();

        let mut sdk = Self {
            owner_id: owner_id.to_string(),
            app_name: app_name.to_string(),
            version: version.to_string(),
            secret: secret.to_string(),
            base_url: base,
            debug,
            session_id: String::new(),
            initialized: false,
            application_hash: String::new(),
            cached_ip: String::new(),
            cached_ip_expires_at_ms: 0,
            response: Response::default(),
            user_data: UserData::default(),
            variable_data: VariableData::default(),
            update_data: UpdateData::default(),
            http,
        };

        sdk.application_hash = sdk.get_current_application_hash();
        sdk.log(format!(
            "[SDK] AuthlyX initialized for app '{}' using '{}'.",
            sdk.app_name, sdk.base_url
        ));

        sdk
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as i64
    }

    fn reset_response(&mut self) {
        self.response = Response::default();
    }

    fn fail(&mut self, code: &str, msg: &str, raw: &str, status: u16) -> bool {
        self.response.success = false;
        self.response.code = code.to_string();
        self.response.message = msg.to_string();
        self.response.raw = raw.to_string();
        self.response.status_code = status;
        false
    }

    fn ensure_initialized(&mut self) -> bool {
        if self.initialized && !self.session_id.is_empty() {
            return true;
        }
        self.fail("NOT_INITIALIZED", "AuthlyX is not initialized. Call Init() first.", "", 0)
    }

    fn safe_dir(s: &str) -> String {
        let t = s.trim();
        if t.is_empty() {
            return "default".to_string();
        }
        t.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
            .collect()
    }

    fn log_root(&self) -> PathBuf {
        if cfg!(windows) {
            if let Ok(pd) = std::env::var("PROGRAMDATA") {
                return PathBuf::from(pd).join("AuthlyX").join(Self::safe_dir(&self.app_name));
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".authlyx").join(Self::safe_dir(&self.app_name))
    }

    fn mask_sensitive(&self, s: &str) -> String {
        let mut out = s.to_string();
        for k in [
            "session_id",
            "owner_id",
            "secret",
            "password",
            "key",
            "license_key",
            "hash",
            "request_id",
            "nonce",
            "hwid",
            "sid",
        ] {
            out = out.replace(&format!("\"{}\":\"", k), &format!("\"{}\":\"***", k));
        }
        out
    }

    fn log(&self, content: String) {
        if !self.debug {
            return;
        }
        if content.trim().is_empty() {
            return;
        }

        let root = self.log_root();
        let _ = fs::create_dir_all(&root);
        let file = root.join(format!("{}.log", utc_date_key()));
        let line = format!("[{}] {}\n", utc_time_key(), self.mask_sensitive(&content));

        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(file) {
            let _ = f.write_all(line.as_bytes());
        }
    }

    fn create_security_context(&self) -> (String, String, i64) {
        let request_id = Uuid::new_v4().to_string();
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        let nonce = hex::encode(b);
        let ts = Self::now_ms();
        (request_id, nonce, ts)
    }

    fn build_url(&self, endpoint: &str) -> String {
        format!("{}/{}", self.base_url, endpoint.trim_start_matches('/'))
    }

    fn post_json(&mut self, endpoint: &str, mut payload: Value) -> (Value, bool) {
        self.reset_response();

        let (request_id, nonce, ts) = self.create_security_context();
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("request_id".to_string(), Value::String(request_id.clone()));
            obj.insert("nonce".to_string(), Value::String(nonce.clone()));
            obj.insert("timestamp".to_string(), Value::Number(ts.into()));
        }

        let body = payload.to_string();
        let url = self.build_url(endpoint);
        self.log(format!("[SDK][REQUEST] POST {} {}", url, body));

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&format!("AuthlyX-Rust-Client/{}", self.version)).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-request-id"),
            HeaderValue::from_str(&request_id).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-auth-nonce"),
            HeaderValue::from_str(&nonce).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-auth-timestamp"),
            HeaderValue::from_str(&ts.to_string()).unwrap(),
        );

        let res = match self.http.post(url).headers(headers).body(body).send() {
            Ok(r) => r,
            Err(e) => {
                self.fail("NETWORK_ERROR", &format!("Network error: {}", e), "", 0);
                return (Value::Null, false);
            }
        };

        let status = res.status().as_u16();
        let hdrs = res.headers().clone();
        let raw = res.text().unwrap_or_default();
        self.log(format!("[SDK][RESPONSE] {} {}", status, raw));

        self.response.raw = raw.clone();
        self.response.status_code = status;
        self.response.request_id = request_id.clone();
        self.response.nonce = nonce.clone();
        self.response.signature_kid = hdrs
            .get("x-v2-signature-kid")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if let Some(v) = hdrs.get("x-v2-request-id").and_then(|v| v.to_str().ok()) {
            if !v.is_empty() && v != request_id {
                self.fail(
                    "AUTH_REQUEST_MISMATCH",
                    "Response request_id does not match the original request.",
                    &raw,
                    status,
                );
                return (Value::Null, false);
            }
        }
        if let Some(v) = hdrs.get("x-v2-nonce").and_then(|v| v.to_str().ok()) {
            if !v.is_empty() && v != nonce {
                self.fail(
                    "AUTH_REQUEST_MISMATCH",
                    "Response nonce does not match the original request.",
                    &raw,
                    status,
                );
                return (Value::Null, false);
            }
        }

        let obj: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => {
                self.fail("INVALID_JSON", "Invalid JSON response from server.", &raw, status);
                return (Value::Null, false);
            }
        };

        self.response.success = obj
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(status >= 200 && status < 300);
        self.response.message = obj.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string();
        self.response.code = obj.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !self.response.success && self.response.code.is_empty() {
            self.response.code = status.to_string();
        }

        if let Some(s) = obj.get("session_id").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                self.session_id = s.to_string();
            }
        }

        self.load_user_data(&obj);
        self.load_variable_data(&obj);
        self.load_update_data(&obj);

        (obj, self.response.success)
    }

    pub fn init(&mut self) -> bool {
        if self.owner_id.trim().is_empty()
            || self.app_name.trim().is_empty()
            || self.version.trim().is_empty()
            || self.secret.trim().is_empty()
        {
            return self.fail(
                "MISSING_CREDENTIALS",
                "Owner ID, app name, version, and secret are required.",
                "",
                0,
            );
        }

        let payload = json!({
            "owner_id": self.owner_id,
            "app_name": self.app_name,
            "version": self.version,
            "secret": self.secret,
            "hash": self.get_current_application_hash()
        });

        let (_obj, ok) = self.post_json("init", payload);
        self.initialized = ok && !self.session_id.is_empty();
        self.initialized
    }

    pub fn login(&mut self, identifier: &str, password: Option<&str>, device_type: Option<&str>) -> bool {
        if let Some(dt) = device_type {
            return self.device_login(dt, identifier);
        }
        if password.is_none() {
            return self.license_login(identifier);
        }
        self.user_login(identifier, password.unwrap_or(""))
    }

    pub fn user_login(&mut self, username: &str, password: &str) -> bool {
        if !self.ensure_initialized() {
            return false;
        }
        let payload = json!({
            "session_id": self.session_id,
            "username": username,
            "password": password,
            "sid": self.get_system_identifier(),
            "ip": self.get_public_ip()
        });
        let (_obj, ok) = self.post_json("login", payload);
        ok
    }

    pub fn license_login(&mut self, license_key: &str) -> bool {
        if !self.ensure_initialized() {
            return false;
        }
        let payload = json!({
            "session_id": self.session_id,
            "license_key": license_key,
            "sid": self.get_system_identifier(),
            "ip": self.get_public_ip()
        });
        let (_obj, ok) = self.post_json("licenses", payload);
        ok
    }

    pub fn device_login(&mut self, device_type: &str, device_id: &str) -> bool {
        if !self.ensure_initialized() {
            return false;
        }
        let payload = json!({
            "session_id": self.session_id,
            "device_type": device_type.trim().to_lowercase(),
            "device_id": device_id,
            "ip": self.get_public_ip()
        });
        let (_obj, ok) = self.post_json("device-auth", payload);
        ok
    }

    pub fn register(&mut self, username: &str, password: &str, license_key: &str, email: &str) -> bool {
        if !self.ensure_initialized() {
            return false;
        }
        let payload = json!({
            "session_id": self.session_id,
            "username": username,
            "password": password,
            "key": license_key,
            "email": email,
            "hwid": self.get_system_identifier()
        });
        let (_obj, ok) = self.post_json("register", payload);
        ok
    }

    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> bool {
        if !self.ensure_initialized() {
            return false;
        }
        let payload = json!({
            "session_id": self.session_id,
            "old_password": old_password,
            "new_password": new_password
        });
        let (_obj, ok) = self.post_json("change-password", payload);
        ok
    }

    pub fn extend_time(&mut self, username: &str, license_key: &str) -> bool {
        if !self.ensure_initialized() {
            return false;
        }
        let payload = json!({
            "session_id": self.session_id,
            "username": username,
            "license_key": license_key,
            "sid": self.get_system_identifier(),
            "ip": self.get_public_ip()
        });
        let (_obj, ok) = self.post_json("extend", payload);
        ok
    }

    pub fn set_variable(&mut self, key: &str, value: &str) -> bool {
        if !self.ensure_initialized() {
            return false;
        }
        let payload = json!({
            "session_id": self.session_id,
            "var_key": key,
            "var_value": value
        });
        let (_obj, ok) = self.post_json("variables/set", payload);
        ok
    }

    pub fn get_variable(&mut self, key: &str) -> Option<String> {
        if !self.ensure_initialized() {
            return None;
        }
        let payload = json!({
            "session_id": self.session_id,
            "var_key": key
        });
        let (_obj, ok) = self.post_json("variables", payload);
        if !ok {
            return None;
        }
        Some(self.variable_data.var_value.clone())
    }

    pub fn validate_session(&mut self) -> bool {
        if !self.initialized || self.session_id.is_empty() {
            return self.fail("INVALID_SESSION", "No active session. Please login first.", "", 0);
        }
        let payload = json!({ "session_id": self.session_id });
        let (_obj, ok) = self.post_json("validate-session", payload);
        ok
    }

    pub fn get_system_identifier(&self) -> String {
        if cfg!(windows) {
            if let Some(sid) = windows_sid() {
                return sid;
            }
        }
        let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default();
        let host = std::env::var("COMPUTERNAME").unwrap_or_default();
        let seed = format!("{}|{}|{}", user, host, std::env::consts::OS);
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        hex::encode(h.finalize())
    }

    pub fn get_public_ip(&mut self) -> String {
        let now = Self::now_ms();
        if !self.cached_ip.is_empty() && now < self.cached_ip_expires_at_ms {
            return self.cached_ip.clone();
        }
        let ip = match self.http.get("https://api.ipify.org").send() {
            Ok(r) => r.text().unwrap_or_default(),
            Err(_) => String::new(),
        };
        let ip = ip.trim().to_string();
        if !ip.is_empty() {
            self.cached_ip = ip;
            self.cached_ip_expires_at_ms = now + 10 * 60 * 1000;
        }
        self.cached_ip.clone()
    }

    pub fn get_current_application_hash(&self) -> String {
        let file = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return "UNKNOWN_HASH".to_string(),
        };
        let b = fs::read(file).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(&b);
        hex::encode(h.finalize())
    }

    fn load_user_data(&mut self, obj: &Value) {
        let user = obj.get("user").and_then(|v| v.as_object());
        let lic = obj.get("license").and_then(|v| v.as_object());
        let dev = obj.get("device").and_then(|v| v.as_object());

        if let Some(u) = user {
            self.user_data.username = u.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let email = u.get("email").and_then(|v| v.as_str()).unwrap_or("");
            if !email.is_empty() {
                self.user_data.email = email.to_string();
            }
            let sub = u.get("subscription").and_then(|v| v.as_str()).unwrap_or("");
            if !sub.is_empty() {
                self.user_data.subscription = sub.to_string();
            }
            if self.user_data.subscription_level.is_empty() {
                if let Some(lvl) = u.get("subscription_level") {
                    if !lvl.is_null() {
                        self.user_data.subscription_level = lvl.to_string().trim_matches('"').to_string();
                    }
                }
            }
            let exp = u.get("expiry_date").and_then(|v| v.as_str()).unwrap_or("");
            if !exp.is_empty() {
                self.user_data.expiry_date = exp.to_string();
            }
            let ll = u.get("last_login").and_then(|v| v.as_str()).unwrap_or("");
            if !ll.is_empty() {
                self.user_data.last_login = ll.to_string();
            }
            let ra = u.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
            if !ra.is_empty() {
                self.user_data.registered_at = ra.to_string();
            }
        }

        if let Some(l) = lic {
            let lk = l.get("license_key").and_then(|v| v.as_str()).unwrap_or("");
            if !lk.is_empty() {
                self.user_data.license_key = lk.to_string();
            }
            let sub = l.get("subscription").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.subscription.is_empty() && !sub.is_empty() {
                self.user_data.subscription = sub.to_string();
            }
            if self.user_data.subscription_level.is_empty() {
                if let Some(lvl) = l.get("subscription_level") {
                    if !lvl.is_null() {
                        self.user_data.subscription_level = lvl.to_string().trim_matches('"').to_string();
                    }
                }
            }
            let exp = l.get("expiry_date").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.expiry_date.is_empty() && !exp.is_empty() {
                self.user_data.expiry_date = exp.to_string();
            }
        }

        if let Some(d) = dev {
            let sub = d.get("subscription").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.subscription.is_empty() && !sub.is_empty() {
                self.user_data.subscription = sub.to_string();
            }
            if self.user_data.subscription_level.is_empty() {
                if let Some(lvl) = d.get("subscription_level") {
                    if !lvl.is_null() {
                        self.user_data.subscription_level = lvl.to_string().trim_matches('"').to_string();
                    }
                }
            }
            let exp = d.get("expiry_date").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.expiry_date.is_empty() && !exp.is_empty() {
                self.user_data.expiry_date = exp.to_string();
            }
            let ll = d.get("last_login").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.last_login.is_empty() && !ll.is_empty() {
                self.user_data.last_login = ll.to_string();
            }
            let ra = d.get("registered_at").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.registered_at.is_empty() && !ra.is_empty() {
                self.user_data.registered_at = ra.to_string();
            }
            let ip = d.get("ip_address").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.ip_address.is_empty() && !ip.is_empty() {
                self.user_data.ip_address = ip.to_string();
            }
            let hw = d.get("hwid").and_then(|v| v.as_str()).unwrap_or("");
            if self.user_data.hwid.is_empty() && !hw.is_empty() {
                self.user_data.hwid = hw.to_string();
            }
        }

        if self.user_data.hwid.is_empty() {
            self.user_data.hwid = self.get_system_identifier();
        }
        if self.user_data.ip_address.is_empty() {
            self.user_data.ip_address = self.get_public_ip();
        }

        self.user_data.days_left = compute_days_left(&self.user_data.expiry_date);
    }

    fn load_variable_data(&mut self, obj: &Value) {
        if let Some(v) = obj.get("variable").and_then(|v| v.as_object()) {
            self.variable_data.var_key = v.get("var_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
            self.variable_data.var_value = v.get("var_value").and_then(|v| v.as_str()).unwrap_or("").to_string();
            self.variable_data.updated_at = v.get("updated_at").and_then(|v| v.as_str()).unwrap_or("").to_string();
        }
    }

    fn load_update_data(&mut self, obj: &Value) {
        if let Some(u) = obj.get("update").and_then(|v| v.as_object()) {
            self.update_data.available = u.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
            self.update_data.latest_version = u.get("latest_version").and_then(|v| v.as_str()).unwrap_or("").to_string();
            self.update_data.download_url = u.get("download_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
            self.update_data.force_update = u.get("force_update").and_then(|v| v.as_bool()).unwrap_or(false);
            self.update_data.changelog = u.get("changelog").and_then(|v| v.as_str()).unwrap_or("").to_string();
            self.update_data.show_reminder = u.get("show_reminder").and_then(|v| v.as_bool()).unwrap_or(false);
            self.update_data.reminder_message = u.get("reminder_message").and_then(|v| v.as_str()).unwrap_or("").to_string();
            self.update_data.allowed_until = u.get("allowed_until").and_then(|v| v.as_str()).unwrap_or("").to_string();
        }
    }
}

fn windows_sid() -> Option<String> {
    let out = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return None;
    }
    let cols: Vec<String> = s
        .split(',')
        .map(|c| c.trim().trim_matches('"').to_string())
        .collect();
    for c in &cols {
        if c.starts_with("S-1-") {
            return Some(c.clone());
        }
    }
    None
}

fn compute_days_left(expiry: &str) -> i64 {
    if expiry.trim().is_empty() {
        return 0;
    }
    let s = expiry.trim().replace('Z', "+00:00");
    let dt = OffsetDateTime::parse(&s, &Rfc3339).ok();
    if dt.is_none() {
        return 0;
    }
    let dt = dt.unwrap();
    let now = OffsetDateTime::now_utc();
    let diff = dt - now;
    let days = diff.whole_days();
    if days < 0 {
        0
    } else {
        days
    }
}

fn utc_date_key() -> String {
    let now = OffsetDateTime::now_utc();
    format!("{:04}_{:02}_{:02}", now.year(), u8::from(now.month()), now.day())
}

fn utc_time_key() -> String {
    let now = OffsetDateTime::now_utc();
    format!("{:02}:{:02}:{:02}", now.hour(), now.minute(), now.second())
}
