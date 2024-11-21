use extism_pdk::{debug,plugin_fn,FnResult,Json};
use serde::{Serialize,Deserialize};
use url::{Url};
use std::collections::BTreeMap;

const HEADER_TMPL: &str = include_str!("../templates/header.html");

#[derive(Serialize)]
struct HeaderData {
    name: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct HttpRequest {
    pub url: String,
    pub headers: BTreeMap<String, Vec<String>>,
    pub method: Option<String>,
}

#[derive(Debug,Serialize)]
struct HttpResponse {
    pub code: u32,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: String,
}

impl HttpResponse {
    fn new(code: u32, body: &str) -> Self {
        Self{
            code,
            body: body.to_string(),
            headers: BTreeMap::new(),
        }
    }
}

#[plugin_fn]
pub extern "C" fn handle(Json(req): Json<HttpRequest>) -> FnResult<Json<HttpResponse>> {

    let u = Url::parse(&req.url).unwrap();

    debug!("{:?}", req);
    debug!("{:?}", req.url);
    debug!("{:?}", u);

    let mut res = match u.path() {
        "/" => {

            let template = mustache::compile_str(HEADER_TMPL).unwrap();
            //let data = HeaderData { name: name.to_string() };
            let data = HeaderData { name: "Anders".to_string() };
            let body = template.render_to_string(&data).unwrap();

            HttpResponse::new(200, &body)
        },
        _ => {
            HttpResponse::new(404, "Not found")
        }
    };

    res.headers = BTreeMap::from([
        ("og".to_string(), vec!["Hi there".to_string()]),
    ]);

    Ok(Json(res))
}
