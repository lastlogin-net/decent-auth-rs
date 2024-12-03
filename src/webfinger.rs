use webfinger;
use url::{Url};
use crate::{error,HttpRequest,Method,HeaderMap,DaError};

#[cfg(target_arch = "wasm32")]
use crate::http_client;
#[cfg(not(target_arch = "wasm32"))]
use openidconnect::reqwest::http_client;

pub fn resolve(handle: &str) -> error::Result<webfinger::Webfinger> {

    let url = webfinger::url_for(webfinger::Prefix::Acct, handle, true)
        .map_err(|_| DaError::new("Failed to parse"))?;
    let parsed_url = Url::parse(&url)?;
    let req = HttpRequest{
        url: parsed_url,
        method: Method::GET, 
        headers: HeaderMap::new(),
        body: vec![],
    };
    let res = http_client(req)?;

    let wf: webfinger::Webfinger = serde_json::from_slice(&res.body)?;

    Ok(wf)
}
