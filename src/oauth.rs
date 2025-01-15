use crate::{
    DaHttpRequest,KvStore,Config,Templater,DaHttpResponse,kv,error,
    parse_params,generate_random_text,get_session,SessionBuilder,SESSION_PREFIX,
};
use std::collections::{HashMap,BTreeMap};
use url::Url;

pub fn handle<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config, _templater: &Templater) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 
    let path = parsed_url.path();
    let params = parse_params(&req).unwrap_or(HashMap::new());

    if path == &format!("{}/oauth/authorize", config.path_prefix) {

        let session = if let Some(session) = get_session(&req, &kv_store, config) {
            session
        }
        else {
            let mut res = DaHttpResponse::new(303, "");
            //let ret = urlencoding::encode(&req.url);
            let uri = format!("{}?return_target={}?{}", config.path_prefix, path, parsed_url.query().unwrap());
            res.headers = BTreeMap::from([
                ("Location".to_string(), vec![uri]),
            ]);
            return Ok(res);

        };

        println!("authorize: {:?}", session);

        let redirect_uri = params.get("redirect_uri").unwrap();

        let token = generate_random_text();
        let location = format!("{}?token={}", redirect_uri, token);

        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &token);
        let new_session = SessionBuilder::new(session.id_type, &session.id)
            .build();
        kv_store.set(&kv_session_key, &new_session)?;

        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![location]),
        ]);

        return Ok(res);
    }
    else if path == &format!("{}/oauth/approve", config.path_prefix) {
        println!("approve");
    }
    else if path == &format!("{}/oauth/token", config.path_prefix) {
        println!("token");
    }

    Ok(DaHttpResponse::new(200, ""))
}
