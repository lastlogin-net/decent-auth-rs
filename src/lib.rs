use extism_pdk::{info,plugin_fn,FnResult,Json,HttpRequest};
use serde::{Serialize};
use url::{Url};

const HEADER_TMPL: &str = include_str!("../templates/header.html");

#[derive(Serialize)]
struct HeaderData {
    name: String,
}

#[derive(Serialize)]
struct HttpResponse {
    code: u32,
    body: String,
}

#[plugin_fn]
pub extern "C" fn handle(Json(req): Json<HttpRequest>) -> FnResult<Json<HttpResponse>> {

    info!("{:?}", req.url);

    let u = Url::parse(&req.url).unwrap();
    info!("{:?}", u);

    let res = match u.path() {
        "/" => {

            let template = mustache::compile_str(HEADER_TMPL).unwrap();
            //let data = HeaderData { name: name.to_string() };
            let data = HeaderData { name: "Anders".to_string() };
            let body = template.render_to_string(&data).unwrap();

            HttpResponse{
                code: 200,
                body,
            } 
        },
        "/logout" => {
            HttpResponse{
                code: 404,
                body: "Not implemented".to_string(),
            } 
        },
        _ => {
            HttpResponse{
                code: 404,
                body: "Not found".to_string(),
            } 
        }
    };


    Ok(Json(res))
}
