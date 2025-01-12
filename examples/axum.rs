use std::sync::Arc;
use axum::{
    response::{Response,Redirect},
    body::{Body,to_bytes},
    extract::{State,Request},
    routing::{get,any},
    Router,
};
use axum_macros::debug_handler;

use decentauth::{http,LoginMethod,SmtpConfig};
use decentauth_sqlite::KvStore;

struct AppState {
    auth_server: decentauth::Server<KvStore>,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() {

    let args: Vec<String> = std::env::args().collect();

    let port = args[1].clone();
    let db_path = args[2].clone();
    let admin_id = args[3].clone();

    let path_prefix = "/auth";

    let config = decentauth::Config{
        runtime: Some("Rust".to_string()),
        storage_prefix: "decent_auth".to_string(),
        path_prefix: path_prefix.to_string(),
        admin_id: Some(admin_id),
        id_header_name: None,
        login_methods: vec![
            LoginMethod::Oidc {
                uri: "https://lastlogin.net".to_string(),
                name: "LastLogin".to_string(),
            },
            LoginMethod::QrCode,
            LoginMethod::AtProto,
            LoginMethod::Fediverse,
            LoginMethod::Email,
            LoginMethod::FedCm,
            LoginMethod::AdminCode,
        ].into(),
        smtp_config: Some(SmtpConfig{
            server_address: args[4].clone(),
            server_port: args[5].parse::<u16>().expect("Failed to parse port"),
            username: args[6].clone(),
            password: args[7].clone(),
            sender_email: args[8].clone(),
        }),
    };

    let kv_store = KvStore::new(&db_path).unwrap();

    let auth_server = decentauth::Server::new(config, kv_store);

    let state = Arc::new(AppState{
        auth_server,
    });

    let app = Router::new()
        .route("/", get(|| async { Redirect::temporary(path_prefix) }))
        .route(&format!("{}", path_prefix), any(auth_handler))
        .route(&format!("{}/", path_prefix), any(auth_handler))
        .route(&format!("{}/*key", path_prefix), any(auth_handler))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

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
