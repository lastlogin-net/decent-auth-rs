use crate::{
    DaHttpRequest,DaHttpResponse,error,kv,KvStore,Config, get_return_target,get_session,
    Session,SessionBuilder,DaError,generate_random_text,parse_params,
    create_session_cookie,SESSION_PREFIX,template,Templater
};
use url::Url;
use std::collections::{HashMap,BTreeMap};
use qrcode::{QrCode};
use qrcode::render::svg;
use serde::{Serialize,Deserialize};


#[derive(Debug,Serialize,Deserialize)]
struct PendingQrData {
    return_target: String,
    session: Option<Session>,
}

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config, templater: &Templater) -> error::Result<DaHttpResponse> 
    where T: kv::Store,
{
    let parsed_url = Url::parse(&req.url)?; 

    let qr_key = generate_random_text();

    let host = parsed_url.host().ok_or(DaError::new("Failed to parse host"))?;

    let qr_url = format!("https://{}{}/qr?key={}", host, config.path_prefix, qr_key);

    let code = QrCode::new(qr_url);
    let qr_svg = code?.render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    let data = template::QrData{
        config,
        return_target: get_return_target(&req),
        qr_svg,
        qr_key: qr_key.clone(),
    };
    let body = templater.render_qr_code_page(&data)?;


    let storage_key = format!("/{}/pending_qr_logins/{}", config.storage_prefix, qr_key);

    let state = PendingQrData{
        return_target: get_return_target(req),
        session: None,
    };

    kv_store.set(&storage_key, state)?;

    let mut res = DaHttpResponse::new(200, &body);
    res.headers = BTreeMap::from([
        ("Content-Type".to_string(), vec!["text/html".to_string()]),
    ]);

    Ok(res)
}


pub fn handle<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config, templater: &Templater) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 
    let path = parsed_url.path();
    let params = parse_params(&req).unwrap_or(HashMap::new());

    if path == &format!("{}/qr", config.path_prefix) {

        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let session = get_session(&req, &kv_store, config);
        if session.is_none() {
            let mut res = DaHttpResponse::new(303, "");
            let ret = &format!("{}?key={}", path, qr_key);
            let ret = urlencoding::encode(ret);
            let uri = format!("{}?return_target={}", config.path_prefix, ret);
            res.headers = BTreeMap::from([
                ("Location".to_string(), vec![uri]),
            ]);
            return Ok(res);
        }

        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let data = template::QrLinkData {
            config,
            return_target: get_return_target(&req),
            qr_key: qr_key.to_string(),
        };
        let body = templater.render_qr_code_link_page(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        return Ok(res);
    }
    else if path == &format!("{}/qr/approve", config.path_prefix) {

        let params = parse_params(&req).unwrap_or(HashMap::new());

        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let storage_key = format!("/{}/pending_qr_logins/{}", config.storage_prefix, qr_key);

        let mut state: PendingQrData = kv_store.get(&storage_key)?;

        let session = get_session(&req, &kv_store, config).unwrap();

        state.session = Some(session); 

        kv_store.set(&storage_key, state)?;

        let data = template::CommonData{
            config,
            return_target: get_return_target(&req),
        };
        let body = templater.render_qr_approved_page(&data)?;


        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        return Ok(res);
    }
    else if path == &format!("{}/qr/finalize", config.path_prefix) {

        let params = parse_params(&req).unwrap_or(HashMap::new());

        let qr_key = if let Some(key) = params.get("key") {
            key
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("Missing key param")));
        };

        let storage_key = format!("/{}/pending_qr_logins/{}", config.storage_prefix, qr_key);

        let state: PendingQrData = kv_store.get(&storage_key)?;

        let session = if let Some(session) = state.session {
            session
        }
        else {
            return Ok(DaHttpResponse::new(400, &format!("No session")));
        };

        let session_key = generate_random_text();
        let session_cookie = create_session_cookie(&config.storage_prefix, &session_key);

        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);


        let new_session = SessionBuilder::new(session.id_type, &session.id)
            .build();
        kv_store.set(&kv_session_key, &new_session)?;

        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![state.return_target]),
            ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
        ]);

        return Ok(res);
    }

    let res = DaHttpResponse::new(200, "Hi there");
    Ok(res)
}
