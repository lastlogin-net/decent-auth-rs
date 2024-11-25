use extism_pdk::{debug,plugin_fn,host_fn,FnResult,Json,http};
use serde::{Serialize,Deserialize};
use url::{Url};
use std::collections::{HashMap,BTreeMap};
use std::{fmt};
use cookie::{Cookie,time::Duration};
use openidconnect::{
    RedirectUrl,ClientId,IssuerUrl,HttpRequest,HttpResponse,PkceCodeChallenge,
    Scope,Nonce,CsrfToken,PkceCodeVerifier,AuthorizationCode, TokenResponse,
    core::{CoreClient,CoreProviderMetadata,CoreAuthenticationFlow},
    http::{HeaderMap,StatusCode},
};

mod error;

//struct KvReadResult {
//    code: u32,
//    data: Vec<u8>,
//}
//
//impl extism_pdk::FromBytesOwned for KvReadResult {
//    fn from_bytes_owned(data: &[u8]) -> Result<Self, extism_pdk::Error> {
//
//        let res = KvReadResult{
//            code: 0,
//            data: Vec::new(),
//        };
//
//        Ok(res)
//    }
//}

#[host_fn]
extern "ExtismHost" {
    fn kv_read(key: &str) -> Vec<u8>; 
    fn kv_write(key: &str, value: Vec<u8>); 
    fn kv_delete(key: &str); 
}

const SESSION_PREFIX: &str = "sessions";
const OAUTH_STATE_PREFIX: &str = "oauth_state";
const ERROR_CODE_NO_ERROR: u8 = 0;

fn kv_read_json<T: std::fmt::Debug + for<'a> Deserialize<'a>>(key: &str) -> error::Result<T> {
    let bytes = unsafe { kv_read(key)? };
    if bytes[0] != ERROR_CODE_NO_ERROR {
        return Err(Box::new(DaError::new("kv_read bad code")));
    }
    let s = std::str::from_utf8(&bytes[1..])?;
    Ok(serde_json::from_str::<T>(s)?)
}

fn kv_write_json<T: Serialize>(key: &str, value: T) -> error::Result<()> {
    let bytes = serde_json::to_vec(&value)?;
    unsafe { kv_write(key, bytes)? };
    Ok(())
}

const INDEX_TMPL: &str = include_str!("../templates/index.html");

#[derive(Serialize)]
struct IndexTmplData {
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

#[derive(Debug,Serialize,Deserialize)]
struct FlowState {
    pkce_verifier: String,
    nonce: String,
    return_target: String,
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

fn requester(req: HttpRequest) -> std::result::Result<HttpResponse, DaError> {

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

fn get_client(path_prefix: &str, parsed_url: &Url) -> CoreClient {
    let provider_metadata = CoreProviderMetadata::discover(
        &IssuerUrl::new("https://lastlogin.net".to_string()).unwrap(),
        requester,
    ).expect("meta failed");

    let host = parsed_url.host().unwrap();

    let uri = format!("https://{host}{path_prefix}/callback");
    let client =
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(format!("https://{host}")),
            None,
        )
        .set_redirect_uri(RedirectUrl::new(uri).unwrap());

    client
}

#[derive(Debug,Serialize,Deserialize)]
struct Session {
    id: String,
    id_type: String,
}

fn get_session(req: &DaHttpRequest, prefix: &str) -> error::Result<Session> {

    let header_val = req.headers.get("Cookie").ok_or(DaError::new("Failed to get Cookie header"))?;

    let mut session_key_opt: Option<String> = None;

    for cook in Cookie::split_parse(&header_val[0]) {
        if cook.clone()?.name() == format!("{}_session_key", prefix) {
            session_key_opt = Some(format!("/{}/{}/{}", prefix, SESSION_PREFIX, cook?.value().to_string()));
            break;
        }
    }

    let session_key = session_key_opt.ok_or(DaError::new("No session in cookie"))?;
    let session: Session = kv_read_json(&session_key)?;

    Ok(session)
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


#[plugin_fn]
pub extern "C" fn extism_handle(Json(req): Json<DaHttpRequest>) -> FnResult<Json<DaHttpResponse>> {

    let storage_prefix = extism_pdk::config::get("storage_prefix")?.unwrap_or("decent_auth".to_string());
    let path_prefix = extism_pdk::config::get("path_prefix")?.unwrap_or("decent_auth".to_string());

    let result = handle(req, &storage_prefix, &path_prefix);

    if let Ok(res) = result {
        Ok(Json(res))
    }
    else {
        Err(extism_pdk::Error::msg("call to handle failed").into())
    }
}

fn handle(req: DaHttpRequest, storage_prefix: &str, path_prefix: &str) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 

    let session = get_session(&req, &storage_prefix);

    let path = parsed_url.path();

    let res = if path == path_prefix {

        //let name = if let Ok(session) = session {
        //    session.id
        //}
        //else {
        //    "Anonymous".to_string()
        //};

        let template = mustache::compile_str(INDEX_TMPL)?;
        let data = IndexTmplData{ 
            session: session.ok(),
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
    else if path == format!("{}/lastlogin", path_prefix) {

        let client = get_client(&path_prefix, &parsed_url);

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        let flow_state = FlowState{
            pkce_verifier: pkce_verifier.secret().to_string(),
            nonce: nonce.secret().to_string(),
            return_target: get_return_target(&req),
        };

        let state_key = format!("/{}/{}/{}", storage_prefix, OAUTH_STATE_PREFIX, csrf_token.secret());
        kv_write_json(&state_key, flow_state)?;

        let mut res = DaHttpResponse::new(303, "Hi there");

        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![format!("{}", auth_url).to_string()]),
        ]);

        res
    }
    else if path == format!("{}/callback", path_prefix) {

        let hash_query: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

        let client = get_client(&path_prefix, &parsed_url);

        let state = hash_query["state"].clone();

        let state_key = format!("/{}/{}/{}", storage_prefix, OAUTH_STATE_PREFIX, state);
        //debug!("state_key: {:?}", state_key);
        let flow_state: FlowState = kv_read_json(&state_key)?;

        //debug!("flow_state: {:?}", flow_state);

        let code = hash_query["code"].clone();

        let token_response =
            client
                .exchange_code(AuthorizationCode::new(code))
                .set_pkce_verifier(PkceCodeVerifier::new(flow_state.pkce_verifier))
                .request(requester)?;

        let id_token = token_response.id_token().unwrap();

        let nonce = Nonce::new(flow_state.nonce);
        let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;

        let session_key = CsrfToken::new_random().secret().to_string();
        let session_cookie = Cookie::build((format!("{}_session_key", storage_prefix), &session_key))
            .path("/")
            .secure(true)
            .http_only(true);

        let session = Session{
            id_type: "email".to_string(),
            id: claims.subject().to_string(),
        };

        let kv_session_key = format!("/{}/{}/{}", storage_prefix, SESSION_PREFIX, &session_key);
        kv_write_json(&kv_session_key, session)?;

        let mut res = DaHttpResponse::new(303, &format!("{}/callback", path_prefix));

        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![flow_state.return_target]),
            ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
        ]);

        res
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
