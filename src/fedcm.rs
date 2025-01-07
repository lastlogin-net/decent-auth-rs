use crate::{
    DaHttpRequest,DaHttpResponse,KvStore,Config,kv,error,parse_params,
    get_return_target,HEADER_TMPL,FOOTER_TMPL,Session,
    HttpRequest,Method,HeaderMap,HeaderValue,Url,create_session_cookie,
    SESSION_PREFIX,generate_random_text,IdType,SessionBuilder,
};
use std::collections::{HashMap,BTreeMap};
use serde::{Serialize,Deserialize};
use oauth2::{PkceCodeChallenge};

#[cfg(target_arch = "wasm32")]
use crate::http_client;
#[cfg(not(target_arch = "wasm32"))]
use openidconnect::reqwest::http_client;

#[derive(Debug,Clone,Serialize,Deserialize)]
struct FedCmToken {
    code: String,
    metadata_endpoint: String,
}

// TODO: use metadata type from openidconnect-rs
#[derive(Debug,Clone,Serialize,Deserialize)]
struct OAuth2Metadata {
    token_endpoint: String,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
struct IndieAuthResponse {
    me: String,
    profile: IndieAuthProfile,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
struct IndieAuthProfile {
    name: String,
    url: String,
    photo: String,
    email: String,
}

#[derive(Serialize)]
struct TemplateData<'a> {
    config: &'a Config,
    header: &'static str,
    footer: &'static str,
    session: Option<Session>,
    prefix: String,
    return_target: String,
    pkce_code_challenge: String,
    pkce_code_verifier: String,
}

const LOGIN_FEDCM_TMPL: &str = include_str!("../templates/login_fedcm.html");

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> 
where T: kv::Store,
{
    let params = parse_params(&req).unwrap_or(HashMap::new());

    if let Some(token_str) = params.get("token") {

        let pkce_verifier = params.get("pkce_code_verifier").unwrap();

        let token: FedCmToken = serde_json::from_str(token_str).unwrap();

        let url = Url::parse(&token.metadata_endpoint)?;

        let meta_req = HttpRequest{
            url,
            method: Method::GET, 
            headers: HeaderMap::new(),
            body: vec![],
        };
        let meta_res = http_client(meta_req)?;

        let meta: OAuth2Metadata = serde_json::from_slice(&meta_res.body)?;

        let param_str = format!(
            "code={}&client_id=fake-id&client_secret=fake-secret&redirect_uri=fake-redir&grant_type=authorization_code&code_verifier={}",
            token.code,
            pkce_verifier,
        );

        let url = Url::parse(&meta.token_endpoint)?;

        let mut headers = HeaderMap::new();
        let content_type = HeaderValue::from_static("application/x-www-form-urlencoded");
        let accept = HeaderValue::from_static("application/json");
        headers.insert("Content-Type", content_type);
        headers.insert("Accept", accept);

        let token_req = HttpRequest{
            url,
            method: Method::POST, 
            headers,
            body: param_str.as_bytes().to_vec(),
        };
        let token_res = http_client(token_req)?;

        let res: IndieAuthResponse = serde_json::from_slice(&token_res.body)?;

        let session = SessionBuilder::new(IdType::Email, &res.profile.email)
            .build();

        let session_key = generate_random_text();
        let session_cookie = create_session_cookie(&config.storage_prefix, &session_key);

        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
        kv_store.set(&kv_session_key, &session)?;

        let return_target = params.get("return_target").unwrap_or(&"/".to_string()).to_string();

        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![return_target]),
            ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
        ]);

        Ok(res)
    }
    else {

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let template = mustache::compile_str(LOGIN_FEDCM_TMPL)?;
        let data = TemplateData{ 
            config,
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session: None,
            prefix: config.path_prefix.to_string(),
            return_target: get_return_target(&req),
            pkce_code_challenge: pkce_challenge.as_str().to_string(),
            pkce_code_verifier: pkce_verifier.secret().to_string(),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        Ok(res)
    }
}
