use serde::{Serialize,Deserialize};
use url::{Url};
use std::collections::{HashMap,BTreeMap};
use std::{fmt};
use cookie::{Cookie,SameSite,CookieBuilder,time::Duration};
use openidconnect::{
    HttpRequest,
    http::{HeaderMap,HeaderValue,method::Method},
};
use chrono::{DateTime,Utc};
use rand::distributions::{Alphanumeric, DistString};
pub use server::Server;
pub use email::SmtpConfig;
use template::Templater;

#[cfg(target_arch = "wasm32")]
use wasm::http_client;

pub use http;

pub mod webfinger;
mod error;
mod admin_code;
mod qr;
mod oidc;
mod atproto;
mod fediverse;
pub mod kv;
mod server;
#[cfg(target_arch = "wasm32")]
mod wasm;
mod email;
mod fedcm;
mod template;
mod oauth;

#[derive(Debug,Serialize,Deserialize)]
pub struct Config {
    #[serde(default = "default_storage_prefix")]
    pub storage_prefix: String,
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
    pub behind_proxy: bool,
    pub admin_id: Option<String>,
    pub id_header_name: Option<String>,
    pub login_methods: Option<Vec<LoginMethod>>,
    pub smtp_config: Option<email::SmtpConfig>,
    pub runtime: Option<String>,
}

fn default_storage_prefix() -> String {
    "decent_auth".to_string()
}

fn default_path_prefix() -> String {
    "/decent-auth".to_string()
}

const ATPROTO_STR: &str = "ATProto";
const FEDIVERSE_STR: &str = "Fediverse";
const ADMIN_CODE_STR: &str = "Admin Code";
const QR_CODE_STR: &str = "QR Code";
const OIDC_STR: &str = "OIDC";
const EMAIL_STR: &str = "Email";
const FEDCM_STR: &str = "FedCM";

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(tag = "type")]
pub enum LoginMethod {
    #[serde(rename = "ATProto")]
    AtProto,
    Fediverse,
    #[serde(rename = "Admin Code")]
    AdminCode,
    #[serde(rename = "QR Code")]
    QrCode,
    #[serde(rename = "OIDC")]
    Oidc {
        name: String,
        uri: String,
    },
    #[serde(rename = "Email")]
    Email,
    #[serde(rename = "FedCM")]
    FedCm,
}

impl From<serde_json::Error> for kv::Error {
    fn from(_value: serde_json::Error) -> Self {
        Self::new("serde_json::Error")
    }
}


struct KvStore<T: kv::Store> {
    byte_kv: T,
}

impl<T: kv::Store> KvStore<T> {
    fn get<U: for<'a> Deserialize<'a> + std::fmt::Debug>(&self, key: &str) -> Result<U, kv::Error> {
        let bytes = self.byte_kv.get(key)?;
        let serde_res = serde_json::from_slice::<U>(&bytes);
        Ok(serde_res?)
    }

    fn set<U: Serialize>(&self, key: &str, value: U) -> Result<(), kv::Error> {
        let bytes = serde_json::to_vec(&value)?;
        Ok(self.byte_kv.set(key, bytes)?)
    }

    fn delete(&self, key: &str) -> Result<(), kv::Error> {
        Ok(self.byte_kv.delete(key)?)
    }

    //fn list(&self, prefix: &str) -> Result<Vec<String>, kv::Error> {
    //    self.byte_kv.list(prefix)
    //}
}

const SESSION_PREFIX: &str = "sessions";
const OAUTH_STATE_PREFIX: &str = "oauth_state";


#[derive(Debug,Serialize,Deserialize)]
struct DaHttpRequest {
    pub url: String,
    pub headers: BTreeMap<String, Vec<String>>,
    pub method: Option<String>,
    pub body: String,
}

#[derive(Debug,Serialize)]
struct DaHttpResponse {
    pub code: u16,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: String,
}

impl DaHttpResponse {
    fn new(code: u16, body: &str) -> Self {
        Self{
            code,
            body: body.to_string(),
            headers: BTreeMap::new(),
        }
    }
}

#[derive(Debug,Deserialize)]
pub struct DaError {
    msg: String
}

impl DaError {
    fn new(msg: &str) -> Self {
        Self{
            msg: msg.to_string(),
        }
    }
}

impl std::error::Error for DaError {}

impl fmt::Display for DaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DaError: {}", self.msg)
    }
}

impl From<cookie::ParseError> for DaError {
    fn from(_value: cookie::ParseError) -> Self {
        Self::new("cookie::ParseError")
    }
}

impl From<openidconnect::http::status::InvalidStatusCode> for DaError {
    fn from(_value: openidconnect::http::status::InvalidStatusCode) -> Self {
        Self::new("http::status::InvalidStatusCode")
    }
}

impl From<openidconnect::http::header::ToStrError> for DaError {
    fn from(_value: openidconnect::http::header::ToStrError) -> Self {
        Self::new("http::header::ToStrError")
    }
}

impl From<openidconnect::http::header::InvalidHeaderName> for DaError {
    fn from(_value: openidconnect::http::header::InvalidHeaderName) -> Self {
        Self::new("http::header::InvalidHeaderName")
    }
}

impl From<openidconnect::http::header::InvalidHeaderValue> for DaError {
    fn from(_value: openidconnect::http::header::InvalidHeaderValue) -> Self {
        Self::new("http::header::InvalidHeaderValue")
    }
}

#[derive(Debug,Serialize,Deserialize)]
pub struct Session {
    id: String,
    id_type: IdType,
    created_at: DateTime<Utc>,
}

#[derive(Debug,Serialize,Deserialize)]
enum IdType {
    Email,
    AtProto,
    Fediverse,
}

pub struct SessionBuilder {
    id: String,
    id_type: IdType,
}

impl SessionBuilder {
    fn new(id_type: IdType, id: &str) -> Self {
        Self{
            id_type,
            id: id.to_string(),
        }
    }

    fn build(self) -> Session {

        let utc: DateTime<Utc> = Utc::now();

        Session{
            id_type: self.id_type,
            id: self.id,
            created_at: utc,
        }
    }
}

fn get_session<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> Option<Session> {

    //clear_expired_sessions(kv_store, config);

    if let Some(id_header_name) = &config.id_header_name {
        if let Some(ids) = req.headers.get(&id_header_name.to_lowercase()) {
            // TODO: might not be email
            return Some(SessionBuilder::new(IdType::Email, &ids[0]).build());
        }
    }

    if let Some(header_val) = req.headers.get("cookie") {

        let mut session_key_opt: Option<String> = None;

        for cook in Cookie::split_parse(&header_val[0]) {
            if let Ok(cook) = cook.clone() {
                if cook.name() == format!("{}_session_key", config.storage_prefix) {
                    session_key_opt = Some(format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, cook.value().to_string()));
                    break;
                }
            }
        }

        if let Some(session_key) = session_key_opt {
            if let Ok(session) = kv_store.get(&session_key) {
                return Some(session);
            }
        }
    } 

    let params = parse_params(&req).unwrap_or(HashMap::new());

    if let Some(token) = params.get("access_token") {
        let session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &token);
        if let Ok(session) = kv_store.get(&session_key) {
            return Some(session);
        }
    }

    None
}

fn get_return_target(req: &DaHttpRequest) -> String {

    let default = "/".to_string();
    if let Ok(parsed_url) = Url::parse(&req.url) {
        let hash_query: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();
        if let Some(return_target) = hash_query.get("return_target")  {
            if return_target.starts_with("/") {
                return return_target.to_string();
            }
        }
    }

    //debug!("body: {:?}", req.body);
    if let Ok(parsed_body) = Url::parse(&format!("http://example.com/?{}", &req.body)) {
        let hash_query: HashMap<_, _> = parsed_body.query_pairs().into_owned().collect();
        if let Some(return_target) = hash_query.get("return_target")  {
            if return_target.starts_with("/") {
                return return_target.to_string();
            }
        }
    }

    default
}

type Params = HashMap<String, String>;

// TODO: overwrite body params with query params
fn parse_params(req: &DaHttpRequest) -> Option<Params> {

    if let Ok(parsed_url) = Url::parse(&req.url) {
        let hash_query: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();
        if hash_query.len() > 0 {
            return Some(hash_query)
        }
    }

    if let Ok(parsed_body) = Url::parse(&format!("http://example.com/?{}", &req.body)) {
        let hash_query: HashMap<_, _> = parsed_body.query_pairs().into_owned().collect();
        if hash_query.len() > 0 {
            return Some(hash_query)
        }
    }

    None
}

fn handle<T>(req: DaHttpRequest, kv_store: &KvStore<T>, config: &Config, templater: &Templater) -> error::Result<DaHttpResponse> 
    where T: kv::Store
{
    let path_prefix = &config.path_prefix;
    let storage_prefix = &config.storage_prefix;

    let parsed_url = Url::parse(&req.url)?; 

    let session = get_session(&req, &kv_store, config);

    let path = parsed_url.path();

    let res = if path == path_prefix || path == format!("{}/", path_prefix) { 

        let body = match session {
            Some(session) => {
                let data = template::IndexPageData{
                    config,
                    return_target: get_return_target(&req),
                    id: session.id,
                };
                let body = templater.render_index_page(&data)?;
                body
            },
            None => {
                let data = template::CommonData{
                    config,
                    return_target: get_return_target(&req),
                };
                let body = templater.render_login_page(&data)?;
                body
            }
        };

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        res
    }
    else if path == "/" {
        let mut res = DaHttpResponse::new(303, "Redirecting...");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![format!("{}/", path_prefix)]),
        ]);

        res
    }
    else if path == format!("{}/login", path_prefix) {
        let params = parse_params(&req).unwrap_or(HashMap::new());

        let login_type = params.get("type");

        if let Some(login_type) = login_type {
            match login_type.as_str() {
                // TODO: see if we can use actual enum for this
                OIDC_STR => {
                    let oidc_provider = params.get("oidc_provider");
                    if let Some(oidc_provider) = oidc_provider {
                        return oidc::handle_login(&req, kv_store, config, &oidc_provider);
                    }
                    else {
                        return Ok(DaHttpResponse::new(400, "Missing OIDC provider"));
                    }
                },
                QR_CODE_STR => {
                    return qr::handle_login(&req, kv_store, config, templater);
                },
                ADMIN_CODE_STR => {
                    return admin_code::handle_login(&req, kv_store, &params, config, templater);
                },
                ATPROTO_STR => {
                    return atproto::handle_login(&req, kv_store, &config, templater);
                },
                FEDIVERSE_STR => {
                    return fediverse::handle_login(&req, kv_store, &config, templater);
                },
                EMAIL_STR => {
                    return email::handle_login(&req, kv_store, &config, templater);
                },
                FEDCM_STR => {
                    return fedcm::handle_login(&req, kv_store, config, templater);
                },
                &_ => {
                    return Ok(DaHttpResponse::new(400, "Invalid login type"))
                },
            }
        }
        else {
            //debug!("TODO: do discovery");
            // do discovery
        }

        DaHttpResponse::new(200, "")
    }
    else if path.starts_with(&format!("{}/qr", path_prefix)) {
        qr::handle(&req, kv_store, &config, templater)?
    }
    else if path == format!("{}/atproto-client-metadata.json", path_prefix) {
        atproto::handle_client_metadata(&req, kv_store, &config)?
    }
    else if path == format!("{}/atproto-callback", path_prefix) {
        atproto::handle_callback(&req, kv_store, &config)?
    }
    else if path == format!("{}/fediverse-callback", path_prefix) {
        fediverse::handle_callback(&req, kv_store, &config)?
    }
    else if path == format!("{}/callback", path_prefix) {
        oidc::handle_callback(&req, kv_store, &config)?
    }
    else if path == format!("{}/logout", path_prefix) {

        let delete_session_cookie = Cookie::build((format!("{}_session_key", storage_prefix), ""))
            .max_age(Duration::seconds(-1))
            .path("/")
            .secure(true)
            .http_only(true);

        let return_target = get_return_target(&req);

        let mut res = DaHttpResponse::new(303, &format!("{}/callback", path_prefix));
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![return_target]),
            ("Set-Cookie".to_string(), vec![delete_session_cookie.to_string()])
        ]);

        res
    }
    else if path == "/.well-known/oauth-authorization-server" || 
            path.starts_with(&format!("{}/oauth", path_prefix)) {

        oauth::handle(&req, kv_store, &config, templater)?
    }
    else {
        DaHttpResponse::new(404, "Not found")
    };

    Ok(res)
}

fn generate_random_text() -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), 32)
}

fn generate_random_key(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), length)
}

fn create_session_cookie<'a>(storage_prefix: &'a str, session_key: &'a str) -> CookieBuilder<'a> {
    Cookie::build((format!("{}_session_key", storage_prefix), session_key))
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(cookie::time::Duration::weeks(4))
        .same_site(SameSite::Lax)
}

fn send_error_page(message: &str, code: u16, req: &DaHttpRequest, config: &Config, templater: &template::Templater) -> error::Result<DaHttpResponse> {

    let data = template::ErrorData{
        config,
        return_target: get_return_target(&req),
        message,
    };

    let body = templater.render_error_page(&data)?;

    let mut res = DaHttpResponse::new(code, &body);
    res.headers = BTreeMap::from([
        ("Content-Type".to_string(), vec!["text/html".to_string()]),
    ]);

    return Ok(res);
}

fn get_host(req: &DaHttpRequest, config: &Config) -> error::Result<String> {
    if config.behind_proxy {
        if let Some(xfh) = req.headers.get("x-forwarded-host") {
            if xfh.len() > 0 {
                return Ok(xfh[0].clone());
            }
        }
        Ok("".to_string())
    }
    else {
        let parsed_url = Url::parse(&req.url)?; 
        let host = parsed_url.host_str().ok_or(DaError::new("Failed to parse host"))?;
        Ok(host.to_string())
    }
}

//const MAX_SESSION_AGE: i64 = 86400;

//fn clear_expired_sessions<T: kv::Store>(kv_store: &KvStore<T>, config: &Config) {
//
//    let now: DateTime<Utc> = Utc::now();
//
//    let session_prefix = format!("/{}/{}/", config.storage_prefix, SESSION_PREFIX);
//
//    if let Ok(session_keys) = kv_store.list(&session_prefix) {
//        for key in session_keys {
//            if let Ok(session) = kv_store.get::<Session>(&key) {
//                let age = now.signed_duration_since(session.created_at);
//                if age.num_seconds() > MAX_SESSION_AGE {
//                    let _ = kv_store.delete(&key);
//                }
//            }
//        }
//    }
//    else {
//        println!("clear_expired_sessions: kv_store.list() failed");
//    }
//}
