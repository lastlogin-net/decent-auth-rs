use std::collections::{BTreeMap};
use crate::{error,Params,DaHttpResponse};
use crate::{debug,http_request,Method,HeaderMap,HttpRequest,Url,Serialize,Deserialize,DaError};

pub fn handle_login(params: &Params, path_prefix: &str) -> error::Result<DaHttpResponse> {

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

        debug!("{:?}", node_info);
    }
    else {
        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![format!("{}/login-fediverse", path_prefix)]),
        ]);
        return Ok(res);
    }

    Ok(DaHttpResponse::new(200, "Hi there"))
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
