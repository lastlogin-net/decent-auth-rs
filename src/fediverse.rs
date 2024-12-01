use std::collections::{HashMap,BTreeMap};
use crate::{
    error,DaHttpResponse,debug,http_request,Method,HeaderMap,HeaderValue,
    HttpRequest,Url,Serialize,Deserialize,DaError,KvStore,Config,kv,
    parse_params,DaHttpRequest,
};

#[derive(Debug,Serialize,Deserialize)]
struct MastodonApp {
    id: String,
    name: String,
    scopes: Vec<String>,
    client_id: String,
    client_secret: String,
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

        let app;
        if let Ok(existing_app) = app_res {
            app = existing_app;
        }
        else {
            let client_name = "Decent Auth Client";
            // TODO: probably don't want to hard code this as https
            let redirect_uris = format!("https://{}{}/fediverse-callback", host, config.path_prefix);
            let scopes = "read:accounts";

            let param_str = format!(
                "client_name={}&redirect_uris={}&scopes={}",
                client_name, redirect_uris, scopes
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

        debug!("app: {:?}", app);
    }
    else {
        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![format!("{}/login-fediverse", config.path_prefix)]),
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
