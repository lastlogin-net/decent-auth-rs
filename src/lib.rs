use extism_pdk::{debug,info,plugin_fn,host_fn,FnResult,Json,http};
use serde::{Serialize,Deserialize};
use url::{Url};
use std::collections::{HashMap,BTreeMap};
use std::{fmt};
use cookie::{Cookie,time::Duration};
use openidconnect::{
    HttpRequest,HttpResponse,CsrfToken,
    http::{HeaderMap,HeaderValue,StatusCode,method::Method},
};

pub mod webfinger;
mod error;
mod admin_code;
mod oidc;
mod fediverse;
mod kv;

#[host_fn]
extern "ExtismHost" {
    fn kv_read(key: &str) -> Vec<u8>; 
    fn kv_write(key: &str, value: Vec<u8>); 
    fn kv_delete(key: &str); 
}

#[derive(Debug,Serialize,Deserialize)]
struct Config {
    storage_prefix: String,
    path_prefix: String,
    admin_id: Option<String>,
    id_header_name: Option<String>,
}


impl From<extism_pdk::Error> for kv::Error {
    fn from(_value: extism_pdk::Error) -> Self {
        Self::new("extism_pdk::Error")
    }
}

impl From<serde_json::Error> for kv::Error {
    fn from(_value: serde_json::Error) -> Self {
        Self::new("serde_json::Error")
    }
}


struct ExtismKv {
}

impl kv::Store for ExtismKv {
    fn get(&self, key: &str) -> Result<Vec<u8>, kv::Error> {
        let bytes = unsafe { kv_read(key)? };
        if bytes[0] != ERROR_CODE_NO_ERROR {
            return Err(kv::Error::new("kv_read bad code"));
        }
        // TODO: I think this to_vec results in an extra copy. Can we avoid it?
        Ok((&bytes[1..]).to_vec())
    }
    
    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), kv::Error> {
        unsafe { kv_write(key, value)? };
        Ok(())
    }

    //fn delete(&self, _key: &str) -> Result<(), kv::Error> {
    //    Err(kv::Error::new("Not implemented"))
    //}
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

    //fn delete(&self, key: &str) -> Result<(), kv::Error> {
    //    Ok(self.byte_kv.delete(key)?)
    //}
}

const SESSION_PREFIX: &str = "sessions";
const OAUTH_STATE_PREFIX: &str = "oauth_state";
const ERROR_CODE_NO_ERROR: u8 = 0;

const HEADER_TMPL: &str = include_str!("../templates/header.html");
const FOOTER_TMPL: &str = include_str!("../templates/footer.html");
const INDEX_TMPL: &str = include_str!("../templates/index.html");
const LOGIN_ADMIN_CODE_TMPL: &str = include_str!("../templates/login_admin_code.html");
const LOGIN_FEDIVERSE_TMPL: &str = include_str!("../templates/login_fediverse.html");

#[derive(Serialize)]
struct CommonTemplateData{
    header: &'static str,
    footer: &'static str,
    session: Option<Session>,
    prefix: String,
    return_target: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct DaHttpRequest {
    pub url: String,
    pub headers: BTreeMap<String, Vec<String>>,
    pub method: Option<String>,
    pub body: String,
}

#[derive(Debug,Serialize)]
struct DaHttpResponse {
    pub code: u32,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: String,
}

impl DaHttpResponse {
    fn new(code: u32, body: &str) -> Self {
        Self{
            code,
            body: body.to_string(),
            headers: BTreeMap::new(),
        }
    }
}



pub struct ExtismHttpClient {
}

impl ExtismHttpClient {
    pub fn new() -> Self {
        Self{}
    }
}

#[derive(Debug,Deserialize)]
struct DaError {
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

impl From<extism_pdk::Error> for DaError {
    fn from(_value: extism_pdk::Error) -> Self {
        Self::new("extism_pdk::Error")
    }
}

fn http_request(req: HttpRequest) -> std::result::Result<HttpResponse, DaError> {

    let mut ereq = extism_pdk::HttpRequest{
        url: req.url.to_string(),
        method: Some(req.method.to_string()),
        headers: BTreeMap::new(),
    };

    for (key, value) in req.headers.iter() {
        ereq.headers.insert(key.to_string(), value.to_str().unwrap().to_string());
    }

    let eres = http::request::<Vec<u8>>(&ereq, Some(req.body)).unwrap();

    let res = HttpResponse{
        status_code: StatusCode::from_u16(eres.status_code()).unwrap(),
        body: eres.body(),
        headers: HeaderMap::new(),
    };

    Ok(res)
}

#[derive(Debug,Serialize,Deserialize)]
struct Session {
    id: String,
    id_type: String,
}

fn get_session<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> Option<Session> {

    if let Some(id_header_name) = &config.id_header_name {
        if let Some(ids) = req.headers.get(&id_header_name.to_lowercase()) {
            return Some(Session{
                id: ids[0].clone(),
                id_type: "email".to_string(),
            });
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

fn get_config() -> error::Result<Config> {
    let storage_prefix = extism_pdk::config::get("storage_prefix")?.unwrap_or("decent_auth".to_string());
    let path_prefix = extism_pdk::config::get("path_prefix")?.unwrap_or("decent_auth".to_string());
    let admin_id = extism_pdk::config::get("admin_id")?;
    let id_header_name = extism_pdk::config::get("id_header_name")?;

    let config = Config{
        storage_prefix,
        path_prefix,
        admin_id,
        id_header_name,
    };

    Ok(config)
}


#[plugin_fn]
pub extern "C" fn extism_handle(Json(req): Json<DaHttpRequest>) -> FnResult<Json<DaHttpResponse>> {

    let config = get_config().map_err(|_| DaError::new("Failed to get config for handler"))?;

    let result = handle(req, &config);

    if let Ok(res) = result {
        Ok(Json(res))
    }
    else {
        Err(extism_pdk::Error::msg("call to handle failed").into())
    }
}

#[plugin_fn]
pub extern "C" fn extism_get_session(Json(req): Json<DaHttpRequest>) -> FnResult<Json<Option<Session>>> {
    let config = get_config().map_err(|_| DaError::new("Failed to get config for session"))?;

    let kv_store = KvStore{
        byte_kv: ExtismKv{},
    };

    let session = get_session(&req, &kv_store, &config);

    Ok(Json(session))
}

fn handle(req: DaHttpRequest, config: &Config) -> error::Result<DaHttpResponse> {

    let path_prefix = &config.path_prefix;
    let storage_prefix = &config.storage_prefix;

    let parsed_url = Url::parse(&req.url)?; 

    let kv_store = KvStore{
        byte_kv: ExtismKv{},
    };

    let session = get_session(&req, &kv_store, config);

    let path = parsed_url.path();

    let res = if path == path_prefix {

        let template = mustache::compile_str(INDEX_TMPL)?;
        let data = CommonTemplateData{ 
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session,
            prefix: path_prefix.to_string(),
            return_target: get_return_target(&req),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        res
    }
    else if path == format!("{}/login", path_prefix) {
        let params = parse_params(&req).unwrap_or(HashMap::new());

        let login_type = params.get("type");

        if let Some(login_type) = login_type {
            match login_type.as_str() {
                "oidc" => {
                    let oidc_provider = params.get("oidc_provider");
                    if let Some(oidc_provider) = oidc_provider {
                        return oidc::handle_login(&req, &kv_store, &storage_prefix, &path_prefix, &oidc_provider);
                    }
                    else {
                        return Ok(DaHttpResponse::new(400, "Missing OIDC provider"));
                    }
                },
                "admin-code" => {
                    return admin_code::handle_login(&req, &kv_store, &params, config);
                },
                "fediverse" => {
                    return fediverse::handle_login(&req, &kv_store, &config);
                },
                &_ => {
                    return Ok(DaHttpResponse::new(400, "Invalid login type"))
                },
            }
        }
        else {
            debug!("TODO: do discovery");
            // do discovery
        }

        DaHttpResponse::new(200, "")
    }
    else if path == format!("{}/login-fediverse", path_prefix) {

        let template = mustache::compile_str(LOGIN_FEDIVERSE_TMPL)?;
        let data = CommonTemplateData{ 
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session,
            prefix: path_prefix.to_string(),
            return_target: get_return_target(&req),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        res
    }
    else if path == format!("{}/fediverse-callback", path_prefix) {
        fediverse::handle_callback(&req, &kv_store, &config)?
    }
    else if path == format!("{}/callback", path_prefix) {
        oidc::handle_callback(&req, &kv_store, &config)?
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
    else {
        DaHttpResponse::new(404, "Not found")
    };

    Ok(res)
}

fn generate_random_text() -> String {
    CsrfToken::new_random().secret().to_string()
}
