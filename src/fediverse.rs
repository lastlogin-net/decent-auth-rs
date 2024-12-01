use std::collections::{HashMap,BTreeMap};
use crate::{
    error,DaHttpResponse,http_request,Method,HeaderMap,HeaderValue,
    HttpRequest,Url,Serialize,Deserialize,DaError,KvStore,Config,kv,
    parse_params,DaHttpRequest,generate_random_text,Session,SESSION_PREFIX,
    get_return_target,HEADER_TMPL,FOOTER_TMPL,CommonTemplateData,
    LOGIN_FEDIVERSE_TMPL,get_session,
};
use cookie::{Cookie};

#[derive(Debug,Serialize,Deserialize)]
struct MastodonApp {
    id: String,
    name: String,
    scopes: Vec<String>,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    redirect_uris: Vec<String>,
}

#[derive(Debug,Serialize,Deserialize)]
struct PendingAuthRequest {
    server: String,
    app: MastodonApp,
    return_target: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct CredentialsResponse {
    username: String,
}

pub fn handle_login<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 
    let params = parse_params(&req).unwrap_or(HashMap::new());

    if let Some(fediverse_handle) = params.get("handle") {
        if fediverse_handle == "" || !fediverse_handle.starts_with("@") {
            return Ok(DaHttpResponse::new(400, &format!("Invalid Fediverse handle '{fediverse_handle}'")));
        }

        let handle_parts = fediverse_handle.split("@").collect::<Vec<_>>();

        if handle_parts.len() != 3 {
            return Ok(DaHttpResponse::new(400, &format!("Invalid Fediverse handle '{fediverse_handle}'")));
        }

        let server = handle_parts[2];

        let node_info = get_node_info(server)?;

        if node_info.software.name != "mastodon" {
            return Ok(DaHttpResponse::new(400, &format!("Currently only support Mastodon OAuth")));
        }

        let host = parsed_url.host().ok_or(DaError::new("Failed to parse host"))?;
        let key = format!("/{}/{}/{}/{}", config.storage_prefix, "apps", server, host);

        let app_res: Result<MastodonApp, kv::Error> = kv_store.get(&key);

        let redirect_uri = format!("https://{}{}/fediverse-callback", host, config.path_prefix);

        let app;
        if let Ok(existing_app) = app_res {
            app = existing_app;
        }
        else {
            let client_name = "Decent Auth Client";
            // TODO: probably don't want to hard code this as https
            let scopes = "read:accounts";

            let param_str = format!(
                "client_name={}&redirect_uris={}&scopes={}",
                client_name, redirect_uri, scopes
            );

            let url = Url::parse(&format!("https://{}/api/v1/apps", server))?;

            let mut headers = HeaderMap::new();
            let content_type = HeaderValue::from_static("application/x-www-form-urlencoded");
            headers.insert("Content-Type", content_type);

            let req = HttpRequest{
                url,
                method: Method::POST, 
                headers,
                body: param_str.as_bytes().to_vec(),
            };
            let res = http_request(req)?;

            let new_app: MastodonApp = serde_json::from_slice(&res.body)?;

            kv_store.set(&key, &new_app)?;

            app = new_app;
        }


        let state = generate_random_text();
        let auth_uri = format!("https://{}/oauth/authorize?client_id={}&redirect_uri={}&state={}&response_type=code&scope=read:accounts", server, app.client_id, redirect_uri, state);

        let oauth_state_key = format!("/{}/{}/{}", config.storage_prefix, "oauth_state", state);

        let auth_req = PendingAuthRequest{
            server: server.to_string(),
            app,
            return_target: get_return_target(req),
        };

        kv_store.set(&oauth_state_key, auth_req)?;

        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![auth_uri]),
        ]);
        return Ok(res);
    }
    else {

        let session = get_session(&req, &kv_store, config);

        let template = mustache::compile_str(LOGIN_FEDIVERSE_TMPL)?;
        let data = CommonTemplateData{ 
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session,
            prefix: config.path_prefix.to_string(),
            return_target: get_return_target(&req),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        Ok(res)
    }
}


pub fn handle_callback<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

    let params = parse_params(&req).unwrap_or(HashMap::new());

    let state = params.get("state").ok_or(DaError::new("Missing state param"))?;
    let code = params.get("code").ok_or(DaError::new("Missing code param"))?;

    let oauth_state_key = format!("/{}/{}/{}", config.storage_prefix, "oauth_state", state);
    let auth_req: PendingAuthRequest = kv_store.get(&oauth_state_key)?;
    let app = &auth_req.app;

    let param_str = format!(
        "code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code",
        code, app.client_id, app.client_secret, app.redirect_uri,
    );

    let url = Url::parse(&format!("https://{}/oauth/token", auth_req.server))?;

    let mut headers = HeaderMap::new();
    let content_type = HeaderValue::from_static("application/x-www-form-urlencoded");
    let accept = HeaderValue::from_static("application/json");
    headers.insert("Content-Type", content_type);
    headers.insert("Accept", accept);

    let req = HttpRequest{
        url,
        method: Method::POST, 
        headers,
        body: param_str.as_bytes().to_vec(),
    };
    let res = http_request(req)?;

    let token_res: TokenResponse = serde_json::from_slice(&res.body)?;

    let url = Url::parse(&format!("https://{}/api/v1/accounts/verify_credentials", auth_req.server))?;

    let mut headers = HeaderMap::new();
    let authorization = HeaderValue::from_str(&format!("Bearer {}", token_res.access_token))?;
    headers.insert("Authorization", authorization);

    let req = HttpRequest{
        url,
        method: Method::GET, 
        headers,
        body: vec![],
    };
    let res = http_request(req)?;

    let cred_res: CredentialsResponse = serde_json::from_slice(&res.body)?;

    let id = format!("@{}@{}", cred_res.username, auth_req.server);

    let session = Session{
        id_type: "fediverse".to_string(),
        id,
    };

    let session_key = generate_random_text();
    let session_cookie = Cookie::build((format!("{}_session_key", config.storage_prefix), &session_key))
        .path("/")
        .secure(true)
        .http_only(true);

    let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
    kv_store.set(&kv_session_key, &session)?;

    let mut res = DaHttpResponse::new(303, "");
    res.headers = BTreeMap::from([
        ("Location".to_string(), vec![auth_req.return_target]),
        ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
    ]);

    Ok(res)
}

#[derive(Debug,Serialize,Deserialize)]
struct NodeInfo {
    software: Software,
}

#[derive(Debug,Serialize,Deserialize)]
struct Software {
    name: String,
    version: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct NodeInfoWellKnown {
    links: Vec<Link>,
}

#[derive(Debug,Serialize,Deserialize)]
struct Link {
    rel: String,
    href: String,
}

fn get_node_info(server: &str) -> error::Result<NodeInfo> {

    let url = format!("https://{}/.well-known/nodeinfo", server);

    let parsed_url = Url::parse(&url)?;
    let req = HttpRequest{
        url: parsed_url,
        method: Method::GET, 
        headers: HeaderMap::new(),
        body: vec![],
    };

    let res = http_request(req)?;

    let node_info_well_known: NodeInfoWellKnown = serde_json::from_slice(&res.body)?;

    let mut found_link: Option<Link> = None;

    for link in node_info_well_known.links {
        // TODO: handle other versions
        if link.rel == "http://nodeinfo.diaspora.software/ns/schema/2.0" {
            found_link = Some(link);
        }
    }

    if let Some(link) = found_link {
        let parsed_url = Url::parse(&link.href)?;
        let req = HttpRequest{
            url: parsed_url,
            method: Method::GET, 
            headers: HeaderMap::new(),
            body: vec![],
        };

        let res = http_request(req)?;

        let node_info: NodeInfo = serde_json::from_slice(&res.body)?;

        Ok(node_info)
    }
    else {
        Err(Box::new(DaError{msg:"Bad node info".to_string()}))
    }
}
