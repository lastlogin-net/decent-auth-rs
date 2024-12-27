use crate::{
    DaHttpRequest,DaHttpResponse,error,kv,KvStore,Config,HEADER_TMPL,
    FOOTER_TMPL,get_return_target,get_session,
    Session,DaError,generate_random_text,
};
use url::Url;
use std::collections::BTreeMap;
use qrcode::{QrCode};
use qrcode::render::svg;
use serde::{Serialize};

const LOGIN_QR_CODE_TMPL: &str = include_str!("../templates/login_qr.html");

#[derive(Serialize)]
struct QrTemplateData<'a>{
    config: &'a Config,
    header: &'static str,
    footer: &'static str,
    session: Option<Session>,
    prefix: String,
    return_target: String,
    qr_svg: String,
}

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> 
    where T: kv::Store,
{
    let parsed_url = Url::parse(&req.url)?; 

    let session = get_session(&req, &kv_store, config);

    let key = generate_random_text();

    let host = parsed_url.host().ok_or(DaError::new("Failed to parse host"))?;

    let qr_url = format!("https://{}{}/qr/{}", host, config.path_prefix, key);

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
    };

    let body = template.render_to_string(&data)?;

    let mut res = DaHttpResponse::new(200, &body);
    res.headers = BTreeMap::from([
        ("Content-Type".to_string(), vec!["text/html".to_string()]),
    ]);

    Ok(res)
}


pub fn handle_callback<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {
    let mut res = DaHttpResponse::new(200, "Hi there");
    Ok(res)
}
