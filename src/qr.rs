use crate::{
    DaHttpRequest,DaHttpResponse,error,kv,KvStore,Config,HEADER_TMPL,
    FOOTER_TMPL,get_return_target,get_session,
    Session,SessionBuilder,DaError,generate_random_text,parse_params,
    create_session_cookie,SESSION_PREFIX,
};
use url::Url;
use std::collections::{HashMap,BTreeMap};
use qrcode::{QrCode};
use qrcode::render::svg;
use serde::{Serialize,Deserialize};

const LOGIN_QR_CODE_TMPL: &str = include_str!("../templates/login_qr.html");
const QR_LINK_TMPL: &str = include_str!("../templates/qr_link.html");

#[derive(Serialize)]
struct QrTemplateData<'a>{
    config: &'a Config,
    header: &'static str,
    footer: &'static str,
    session: Option<Session>,
    prefix: String,
    return_target: String,
    qr_svg: String,
    qr_key: String,
}

#[derive(Serialize)]
struct QrLinkTemplateData<'a>{
    config: &'a Config,
    header: &'static str,
    footer: &'static str,
    prefix: String,
    return_target: String,
    qr_key: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct PendingQrData {
    return_target: String,
    session: Option<Session>,
}

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> 
    where T: kv::Store,
{
    let parsed_url = Url::parse(&req.url)?; 

    let session = get_session(&req, &kv_store, config);

    let qr_key = generate_random_text();

    let host = parsed_url.host().ok_or(DaError::new("Failed to parse host"))?;

    let qr_url = format!("https://{}{}/qr?key={}", host, config.path_prefix, qr_key);

    let code = QrCode::new(qr_url);
    let qr_svg = code?.render()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();

    let template = mustache::compile_str(LOGIN_QR_CODE_TMPL)?;
    let data = QrTemplateData {
        config,
        header: HEADER_TMPL,
        footer: FOOTER_TMPL,
        session,
        prefix: config.path_prefix.to_string(),
        return_target: get_return_target(&req),
        qr_svg,
        qr_key: qr_key.clone(),
    };

    let body = template.render_to_string(&data)?;

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


pub fn handle<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

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
            let uri = format!("{}?return_target={}?key={}", config.path_prefix, path, qr_key);
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

        let template = mustache::compile_str(QR_LINK_TMPL)?;

        let data = QrLinkTemplateData {
            config,
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            prefix: config.path_prefix.to_string(),
            return_target: get_return_target(&req),
            qr_key: qr_key.to_string(),
        };

        let body = template.render_to_string(&data)?;
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

        return Ok(DaHttpResponse::new(200, "Approved"));
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
