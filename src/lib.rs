use extism_pdk::{debug,plugin_fn,host_fn,FnResult,Json,http};
use serde::{Serialize,Deserialize};
use url::{Url};
use std::collections::{HashMap,BTreeMap};
use std::{error::Error, fmt};
use cookie::Cookie;
use openidconnect::{
    RedirectUrl,ClientId,IssuerUrl,HttpRequest,HttpResponse,PkceCodeChallenge,
    Scope,Nonce,CsrfToken,PkceCodeVerifier,AuthorizationCode, TokenResponse,
    core::{CoreClient,CoreProviderMetadata,CoreAuthenticationFlow},
    http::{HeaderMap,StatusCode},
};


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
}

fn kv_read_json<T: std::fmt::Debug + for<'a> Deserialize<'a>>(key: &str) -> Result<T, DaError> {
    let bytes = unsafe { kv_read(key).unwrap() };
    if bytes[0] != 65 {
        return Err(DaError{});
    }
    let s = std::str::from_utf8(&bytes[1..]).unwrap();
    Ok(serde_json::from_str::<T>(s).unwrap())
}

fn kv_write_json<T: Serialize>(key: &str, value: T) {
    let bytes = serde_json::to_vec(&value).unwrap();
    unsafe { kv_write(key, bytes).unwrap(); }
}

const HEADER_TMPL: &str = include_str!("../templates/header.html");

#[derive(Serialize)]
struct HeaderData {
    name: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct DaHttpRequest {
    pub url: String,
    pub headers: BTreeMap<String, Vec<String>>,
    pub method: Option<String>,
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
}

impl Error for DaError {}

impl fmt::Display for DaError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DaError")
    }
}

impl From<cookie::ParseError> for DaError {
    fn from(_value: cookie::ParseError) -> Self {
        Self{}
    }
}

impl From<extism_pdk::Error> for DaError {
    fn from(_value: extism_pdk::Error) -> Self {
        Self{}
    }
}

fn requester(req: HttpRequest) -> Result<HttpResponse, DaError> {

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

fn get_client() -> CoreClient {
    let provider_metadata = CoreProviderMetadata::discover(
        &IssuerUrl::new("https://lastlogin.net".to_string()).unwrap(),
        requester,
    ).expect("meta failed");

    let client =
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new("http://localhost:3000".to_string()),
            None,
        )
        .set_redirect_uri(RedirectUrl::new("http://localhost:3000/auth/callback".to_string()).unwrap());

    client
}

#[derive(Debug,Serialize,Deserialize)]
struct Session {
    id: String,
    id_type: String,
}

fn get_session(req: &DaHttpRequest) -> Result<Session, DaError> {

    let header_val = req.headers.get("Cookie").ok_or(DaError{})?;

    let mut session_key_opt: Option<String> = None;

    for cook in Cookie::split_parse(&header_val[0]) {
        if cook.clone()?.name() == "session_key" {
            session_key_opt = Some(format!("sessions/{}", cook?.value().to_string()));
            break;
        }
    }

    let session_key = session_key_opt.ok_or(DaError{})?;
    let session: Session = kv_read_json(&session_key)?;

    Ok(session)
}


#[plugin_fn]
pub extern "C" fn handle(Json(req): Json<DaHttpRequest>) -> FnResult<Json<DaHttpResponse>> {

    let parsed_url = Url::parse(&req.url).unwrap();

    let session = get_session(&req);

    let res = match parsed_url.path() {
        "/auth/" => {

            let name = if let Ok(session) = session {
                session.id
            }
            else {
                "Anonymous".to_string()
            };

            let template = mustache::compile_str(HEADER_TMPL).unwrap();
            let data = HeaderData { name };
            let body = template.render_to_string(&data).unwrap();

            DaHttpResponse::new(200, &body)
        },
        "/auth/lastlogin" => {

            let client = get_client();

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
            };

            let state_key = format!("oauth_state/{}", csrf_token.secret());
            kv_write_json(&state_key, flow_state);

            let mut res = DaHttpResponse::new(303, "Hi there");

            res.headers = BTreeMap::from([
                ("Location".to_string(), vec![format!("{}", auth_url).to_string()]),
            ]);

            res
        }
        "/auth/callback" => {

            let hash_query: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

            let client = get_client();

            let state = hash_query["state"].clone();

            let state_key = format!("oauth_state/{}", state);
            let flow_state: FlowState = kv_read_json(&state_key).unwrap();

            let code = hash_query["code"].clone();

            let token_response =
                client
                    .exchange_code(AuthorizationCode::new(code))
                    .set_pkce_verifier(PkceCodeVerifier::new(flow_state.pkce_verifier))
                    .request(requester).unwrap();

            let id_token = token_response.id_token().unwrap();

            let nonce = Nonce::new(flow_state.nonce);
            let claims = id_token.claims(&client.id_token_verifier(), &nonce).unwrap();

            let session_key = CsrfToken::new_random().secret().to_string();
            let session_cookie = Cookie::build(("session_key", &session_key))
                .path("/")
                .secure(true)
                .http_only(true);

            debug!("cook: {:?}", session_cookie.to_string());

            let session = Session{
                id_type: "email".to_string(),
                id: claims.subject().to_string(),
            };

            let kv_session_key = format!("sessions/{}", &session_key);
            kv_write_json(&kv_session_key, session);

            let mut res = DaHttpResponse::new(303, "/auth/callback");

            res.headers = BTreeMap::from([
                ("Location".to_string(), vec!["/auth/".to_string()]),
                ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
            ]);

            res
        },
        _ => {
            DaHttpResponse::new(404, "Not found")
        }
    };


    Ok(Json(res))
}
