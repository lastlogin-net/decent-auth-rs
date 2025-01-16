use crate::{
    DaHttpRequest,KvStore,Config,Templater,DaHttpResponse,kv,error,
    parse_params,generate_random_text,get_session,SessionBuilder,SESSION_PREFIX,
    get_return_target,template,DaError,Session,send_error_page,
};
use std::collections::{HashMap,BTreeMap};
use url::Url;
use serde::Serialize;

#[derive(Serialize)]
struct TokenResponse<'a> {
    access_token: &'a str,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    message: &'a str,
}

fn send_error_json(message: &str, code: u16) -> error::Result<DaHttpResponse> {

    let error_res = ErrorResponse{
        message,
    };

    let body_json = String::from_utf8(serde_json::to_vec(&error_res)?)?;

    let mut res = DaHttpResponse::new(code, &body_json);
    res.headers = BTreeMap::from([
        ("Access-Control-Allow-Origin".to_string(), vec!["*".to_string()]),
        ("Content-Type".to_string(), vec!["application/json".to_string()]),
    ]);

    return Ok(res);
}

pub fn handle<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config, templater: &Templater) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 
    let path = parsed_url.path();
    let params = parse_params(&req).unwrap_or(HashMap::new());

    if path == &format!("{}/oauth/authorize", config.path_prefix) {

        let raw_query = format!("{}?{}", path, parsed_url.query().unwrap());

        if get_session(&req, &kv_store, config).is_none() {
            let mut res = DaHttpResponse::new(303, "");
            //let ret = urlencoding::encode(&req.url);
            // TODO: I think we need to do nested return_target here
            let uri = format!("{}?return_target={}", config.path_prefix, raw_query);
            res.headers = BTreeMap::from([
                ("Location".to_string(), vec![uri]),
            ]);
            return Ok(res);

        };

        let client_id = if let Some(client_id) = params.get("client_id") {
            client_id
        }
        else {
            println!("here");
            return send_error_page("Missing client_id param", 400, req, config, templater);
        };

        let parsed_client_id = Url::parse(&client_id)?; 
        let client_id_host = parsed_client_id.host().ok_or(DaError::new("Failed to parse host"))?;

        let redirect_uri = if let Some(redirect_uri) = params.get("redirect_uri") {
            redirect_uri
        }
        else {
            return send_error_page("Missing redirect_uri param", 400, req, config, templater);
        };

        if !redirect_uri.starts_with(client_id) {
            return send_error_page("redirect_uri must be on same domain as client_id", 400, req, config, templater);
        }


        let data = template::OAuth2Data{
            config,
            return_target: get_return_target(&req),
            auth_url: &req.url,
            client_id: &client_id_host.to_string(),
        };
        let body = templater.render_oauth_authorize_page(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]); 

        return Ok(res);
    }
    else if path == &format!("{}/oauth/approve", config.path_prefix) {

        let auth_url = params.get("auth_url").unwrap();
        let parsed_auth_url = Url::parse(auth_url)?; 

        let auth_params: HashMap<_, _> = parsed_auth_url.query_pairs().into_owned().collect();

        let session = if let Some(session) = get_session(&req, &kv_store, config) {
            session
        }
        else {
            let mut res = DaHttpResponse::new(303, "");
            // TODO: I think we need to do nested return_target here
            let return_target = format!("{}?{}", path, parsed_auth_url.query().unwrap());
            let uri = format!("{}?return_target={}", config.path_prefix, return_target);
            res.headers = BTreeMap::from([
                ("Location".to_string(), vec![uri]),
            ]);
            return Ok(res);

        };

        let redirect_uri = if let Some(redirect_uri) = auth_params.get("redirect_uri") {
            redirect_uri
        }
        else {
            return send_error_page("Missing redirect_uri param", 400, req, config, templater);
        };

        let code = generate_random_text();
        let location = format!("{}?code={}", redirect_uri, code);

        let key = format!("/{}/pending_oauth_code/{}", config.storage_prefix, code);
        kv_store.set(&key, session)?; 

        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![location]),
        ]);

        return Ok(res);
    }
    else if path == &format!("{}/oauth/token", config.path_prefix) {

        let code = if let Some(code) = params.get("code") {
            code
        }
        else {
            return send_error_json("Missing code param", 400);
        };

        let key = format!("/{}/pending_oauth_code/{}", config.storage_prefix, code);
        let session: Session = if let Ok(session) = kv_store.get(&key) {
            session
        }
        else {
            return send_error_json("No pending OAuth2 request", 400);
        };

        let _ = kv_store.delete(&key); 

        let token = generate_random_text();
        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, token);
        let new_session = SessionBuilder::new(session.id_type, &session.id)
            .build();

        if kv_store.set(&kv_session_key, &new_session).is_err() {
            return send_error_json("Failed to create session", 500);
        }

        let token_res = TokenResponse{
            access_token: &token,
        };

        let body_json = String::from_utf8(serde_json::to_vec(&token_res)?)?;

        let mut res = DaHttpResponse::new(200, &body_json);
        res.headers = BTreeMap::from([
            ("Access-Control-Allow-Origin".to_string(), vec!["*".to_string()]),
            ("Content-Type".to_string(), vec!["application/json".to_string()]),
        ]);

        return Ok(res);
    }

    return send_error_page("Not found", 404, req, config, templater);
}
