use std::{collections::HashMap,sync::{Arc,Mutex}};
use axum::{
    response::{Response,Redirect},
    body::{Body,to_bytes},
    extract::{State,Request},
    routing::{get,post},
    Router,
    //http::header::HeaderMap,
};
use axum_macros::debug_handler;

use decentauth::{http,kv};

struct KvStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl kv::Store for KvStore {
    fn get(&self, key: &str) -> Result<Vec<u8>, kv::Error> {

        let map = self.map.lock().unwrap();

        let value = &map.get(key).ok_or(kv::Error::new("Fail"))?;

        //println!("kv get {}, {:?}", key, value);

        Ok(value.to_vec())
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), kv::Error> {
        //println!("kv set {}, {:?}", key, value);

        let mut map = self.map.lock().unwrap();

        map.insert(key.to_string(), value);

        Ok(())
    }
}

struct AppState {
    auth_server: decentauth::Server<KvStore>,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() {

    let path_prefix = "/auth";

    let config = decentauth::Config{
        storage_prefix: "decent_auth".to_string(),
        path_prefix: path_prefix.to_string(),
        admin_id: Some("anders@apitman.com".to_string()),
        id_header_name: None,
    };

    let kv_store = KvStore{
        map: Mutex::new(HashMap::new()),
    };

    let auth_server = decentauth::Server::new(config, kv_store);

    let state = Arc::new(AppState{
        auth_server,
    });

    let app = Router::new()
        //.route("/", get(handler))
        .route("/", get(|| async { Redirect::temporary(path_prefix) }))
        .route(&format!("{}", path_prefix), get(auth_handler))
        .route(&format!("{}", path_prefix), post(auth_handler))
        .route(&format!("{}/*key", path_prefix), get(auth_handler))
        .route(&format!("{}/*key", path_prefix), post(auth_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

//async fn handler(headers: HeaderMap, State(state): State<SharedState>) -> &'static str {
//
//    let session = state.auth_server.get_session(&headers);
//
//    dbg!(session);
//
//    "Hi there"
//}

#[debug_handler]
async fn auth_handler(State(state): State<SharedState>, req: Request) -> Response<Body> {

    let (parts, body) = req.into_parts();
    let da_body = to_bytes(body, 2*1024*1024).await.unwrap();

    let da_req = http::Request::from_parts(parts, da_body);

    let da_res = tokio::task::spawn_blocking(move || {
        state.auth_server.handle(da_req)
    }).await.unwrap();

    let mut res_builder = Response::builder()
        .status(da_res.status());

    for (key, value) in da_res.headers() {
        res_builder = res_builder.header(key, value);
    }

    let res = res_builder.body(Body::from(da_res.body().clone())).unwrap();

    res
}
