use std::sync::Arc;
use axum::{
    response::{Response,Redirect},
    body::{Body,to_bytes},
    extract::{State,Request},
    routing::{get,post},
    Router,
    //http::header::HeaderMap,
};
use axum_macros::debug_handler;

use decentauth::{http,LoginMethod};
use decentauth_sqlite::KvStore;

struct AppState {
    auth_server: decentauth::Server<KvStore>,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() {

    let args: Vec<String> = std::env::args().collect();

    let admin_id = args[1].clone();

    let path_prefix = "/auth";

    let config = decentauth::Config{
        storage_prefix: "decent_auth".to_string(),
        path_prefix: path_prefix.to_string(),
        admin_id: Some(admin_id),
        id_header_name: None,
        login_methods: vec![
            LoginMethod::Oidc {
                uri: "https://lastlogin.net".to_string(),
                name: "LastLogin".to_string(),
            },
            LoginMethod::AdminCode,
            LoginMethod::QrCode,
            LoginMethod::AtProto,
            LoginMethod::Fediverse,
        ].into(),
    };

    let kv_store = KvStore::new().unwrap();

    let auth_server = decentauth::Server::new(config, kv_store);

    let state = Arc::new(AppState{
        auth_server,
    });

    let app = Router::new()
        //.route("/", get(handler))
        .route("/", get(|| async { Redirect::temporary(path_prefix) }))
        .route(&format!("{}", path_prefix), get(auth_handler))
        .route(&format!("{}", path_prefix), post(auth_handler))
        .route(&format!("{}/", path_prefix), get(auth_handler))
        .route(&format!("{}/", path_prefix), post(auth_handler))
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
