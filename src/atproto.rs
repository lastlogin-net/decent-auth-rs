use std::collections::{HashMap,BTreeMap};
use std::sync::Arc;
use crate::{
    DaHttpRequest,DaHttpResponse,KvStore,Config,error,kv,Url,DaError,
    parse_params,Session,SESSION_PREFIX,generate_random_text,HEADER_TMPL,
    FOOTER_TMPL,get_return_target,get_session,CommonTemplateData,
};
use cookie::Cookie;
use serde::{Serialize,Deserialize};

use atrium_xrpc::HttpClient;
use atrium_api::types::string::Did;
use atrium_common::resolver::Resolver;
use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL};
use atrium_identity::handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig, DnsTxtResolver};
use atrium_oauth_client::store::{SimpleStore,state::{StateStore,InternalStateData}};
use atrium_oauth_client::{
    AuthorizeOptions, KnownScope, OAuthClient,
    OAuthClientConfig, OAuthResolverConfig, Scope, GrantType, AuthMethod,
    AtprotoClientMetadata, OAuthClientMetadata,CallbackParams,
};

#[derive(Debug,Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DnsResponse {
    answer: Vec<Answer>,
}

#[derive(Debug,Deserialize)]
struct Answer {
    data: String,
}

#[derive(Debug,Serialize,Deserialize)]
struct AtPendingAuthRequest {
    return_target: String,
}

type DaOAuthClient<'a, T> = OAuthClient<AtKvStore<'a, T>,CommonDidResolver<AtHttpClient>,AtprotoHandleResolver<AtDnsTxtResolver,AtHttpClient>,AtHttpClient>;

const LOGIN_ATPROTO_TMPL: &str = include_str!("../templates/login_atproto.html");

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> 
where T: kv::Store,
{
    let params = parse_params(&req).unwrap_or(HashMap::new());

    if let Some(handle_or_server) = params.get("handle_or_server") {
        let rt = get_async_runtime()?;

        let client = get_client(req, kv_store, config);

        let state = generate_random_text();
        let oauth_state_key = format!("/{}/{}/{}", config.storage_prefix, "atproto_oauth_state", state);

        let auth_req = AtPendingAuthRequest{
            return_target: get_return_target(req),
        };

        kv_store.set(&oauth_state_key, auth_req)?;

        let redir_res: Result<String, atrium_oauth_client::Error> = rt.block_on(async { 

            let redir_url = client
                .authorize(
                    handle_or_server,
                    AuthorizeOptions {
                        scopes: vec![
                            Scope::Known(KnownScope::Atproto),
                            Scope::Known(KnownScope::TransitionGeneric)
                        ],
                        state: Some(state),
                        ..Default::default()
                    }
                )
                .await;

            redir_url
        });

        let redir_url = redir_res?;

        let mut res = DaHttpResponse::new(303, &format!("Redirect to {}", redir_url));
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![redir_url]),
        ]);

        Ok(res)
    }
    else {
        let session = get_session(&req, &kv_store, config);

        let template = mustache::compile_str(LOGIN_ATPROTO_TMPL)?;
        let data = CommonTemplateData{ 
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session,
            prefix: config.path_prefix.to_string(),
            return_target: get_return_target(&req),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        Ok(res)
    }
}

pub fn handle_callback<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

    let params = parse_params(&req).unwrap_or(HashMap::new());

    let state = params.get("state").ok_or(DaError::new("Missing state param"))?;
    let code = params.get("code").ok_or(DaError::new("Missing code param"))?;
    let iss = params.get("iss").map(|x| x.to_string());

    let callback_params = CallbackParams{
        code: code.to_string(),
        iss,
        state: Some(state.clone()),
    };

    let client = get_client(req, kv_store, config);

    let oauth_state_key = format!("/{}/{}/{}", config.storage_prefix, "atproto_oauth_state", state);
    let auth_req: AtPendingAuthRequest = kv_store.get(&oauth_state_key)?;

    let rt = get_async_runtime()?;
    let session_res: Result<Session, atrium_oauth_client::Error> = rt.block_on(async {
        let res = client.callback(callback_params).await?;

        let did_resolver = CommonDidResolver::new(CommonDidResolverConfig {
            plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
            http_client: Arc::new(AtHttpClient::default()),
        });

        let did_str = res.sub.clone();
        let did = Did::new(did_str).unwrap();
        let did_doc = did_resolver.resolve(&did).await?;

        let id = match did_doc.also_known_as {
            Some(aka) => {
                if aka.len() > 0 && aka[0].len() > 5 {
                    aka[0][5..].to_string()
                }
                else {
                    did_doc.id
                }
            },
            None => did_doc.id,
        };

        let session = Session{
            id_type: "atproto".to_string(),
            id,
        };

        Ok(session)
    });

    let session = session_res?;

    let session_key = generate_random_text();
    let session_cookie = Cookie::build((format!("{}_session_key", config.storage_prefix), &session_key))
        .path("/")
        .secure(true)
        .http_only(true);

    let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
    kv_store.set(&kv_session_key, &session)?;

    let mut res = DaHttpResponse::new(303, "");
    res.headers = BTreeMap::from([
        ("Location".to_string(), vec![auth_req.return_target]),
        ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
    ]);

    Ok(res)
}

pub fn handle_client_metadata<T: kv::Store>(req: &DaHttpRequest, _kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

    let parsed_url = Url::parse(&req.url)?; 
    let host = parsed_url.host().ok_or(DaError::new("Failed to parse host"))?;
    let root_uri = format!("https://{}", host);
    let meta_uri = format!("{}{}/atproto-client-metadata.json", root_uri, config.path_prefix);
    let redirect_uri = format!("{}{}/atproto-callback", root_uri, config.path_prefix);

    let meta = OAuthClientMetadata {
        client_id: meta_uri,
        client_uri: Some(root_uri),
        redirect_uris: vec![redirect_uri],
        token_endpoint_auth_method: Some("none".to_string()),
        grant_types: Some(vec!["authorization_code".to_string()]),
        scope: Some("atproto transition:generic".to_string()),
        dpop_bound_access_tokens: Some(true),
        jwks_uri: None,
        jwks: None,
        token_endpoint_auth_signing_alg: None,
    };

    let body_json = String::from_utf8(serde_json::to_vec(&meta)?)?;

    let mut res = DaHttpResponse::new(200, &body_json);
    res.headers = BTreeMap::from([
        ("Content-Type".to_string(), vec!["application/json".to_string()]),
    ]);

    Ok(res)
}

pub struct AtDnsTxtResolver {
    http_client: AtHttpClient,
}

// TODO: actually implement
impl DnsTxtResolver for AtDnsTxtResolver {
    async fn resolve(
        &self,
        query: &str,
    ) -> core::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync + 'static>> {

        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://cloudflare-dns.com/dns-query?name={}&type=txt", query))
            .header("Accept", "application/dns-json")
            .body(vec![])?;

        let res = self.http_client.send_http(req).await?;

        let dns_res: DnsResponse = serde_json::from_slice(res.body())?;

        let values = dns_res.answer.iter()
            .map(|rec| rec.data.replace("\"", ""))
            .collect::<Vec<_>>();

        Ok(values)
    }
}


#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct AtHttpClient {
    client: reqwest::Client,
}

#[cfg(not(target_arch = "wasm32"))]
impl HttpClient for AtHttpClient {
    async fn send_http(
        &self,
        request: atrium_xrpc::http::Request<Vec<u8>>,
    ) -> core::result::Result<
        atrium_xrpc::http::Response<Vec<u8>>,
        Box<dyn std::error::Error + Send + Sync + 'static>,
    > {
        let response = self.client.execute(request.try_into()?).await?;
        let mut builder = atrium_xrpc::http::Response::builder().status(response.status());
        for (k, v) in response.headers() {
            builder = builder.header(k, v);
        }
        builder.body(response.bytes().await?.to_vec()).map_err(Into::into)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for AtHttpClient {
    fn default() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub struct AtHttpClient {
}

#[cfg(target_arch = "wasm32")]
impl HttpClient for AtHttpClient {
    async fn send_http(
        &self,
        req: atrium_xrpc::http::Request<Vec<u8>>,
    ) -> core::result::Result<
        atrium_xrpc::http::Response<Vec<u8>>,
        Box<dyn std::error::Error + Send + Sync + 'static>,
    > {

        let mut headers = BTreeMap::new();
        for (key, value) in req.headers() {
            let val = value.to_str()?.to_string();
            headers.insert(key.to_string(), val);
        }

        let ereq = extism_pdk::HttpRequest{
            url: req.uri().to_string(),
            method: Some(req.method().to_string()),
            headers,
        };

        let eres = extism_pdk::http::request::<Vec<u8>>(&ereq, Some(req.body().to_vec()))?;

        let mut builder = atrium_xrpc::http::Response::builder()
            .status(eres.status_code());

        for (k, v) in eres.headers() {
            builder = builder.header(k, v);
        }

        let res = builder.body(eres.body());

        Ok(res?)
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for AtHttpClient {
    fn default() -> Self {
        Self {}
    }
}

struct AtKvStore<'a, T: kv::Store> {
    kv_store: &'a KvStore<T>,
}

impl<T> StateStore for AtKvStore<'_, T>
where
    T: kv::Store,
{
}

impl<T> SimpleStore<String, InternalStateData> for AtKvStore<'_, T>
where
    T: kv::Store,
{
    type Error = kv::Error;

    async fn get(&self, key: &String) -> Result<Option<InternalStateData>, Self::Error> {
        let res = self.kv_store.get(key);
        Ok(Some(res?))
    }

    async fn set(&self, key: String, value: InternalStateData) -> Result<(), Self::Error> {
        Ok(self.kv_store.set(&key, value)?)
    }

    async fn del(&self, _key: &String) -> Result<(), Self::Error> {
        // currently no op
        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        // currently no op
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn get_async_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    Ok(rt)
}

#[cfg(target_arch = "wasm32")]
fn get_async_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()?;
    Ok(rt)
}

fn get_client<'a, T>(req: &DaHttpRequest, kv_store: &'a KvStore<T>, config: &Config) -> DaOAuthClient<'a, T>
where T: kv::Store,
{
    let parsed_url = Url::parse(&req.url).unwrap(); 
    let host = parsed_url.host().ok_or(DaError::new("Failed to parse host")).unwrap();

    let shared_http_client = Arc::new(AtHttpClient::default());
    let http_client = AtHttpClient::default();

    let state_store = AtKvStore{
        kv_store,
    };

    let root_uri = format!("https://{}", host);
    let meta_uri = format!("{}{}/atproto-client-metadata.json", root_uri, config.path_prefix);
    let redirect_uri = format!("{}{}/atproto-callback", root_uri, config.path_prefix);

    let client_metadata = AtprotoClientMetadata {
        client_id: meta_uri,
        client_uri: root_uri,
        redirect_uris: vec![redirect_uri],
        token_endpoint_auth_method: AuthMethod::None,
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: vec![Scope::Known(KnownScope::Atproto)],
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
    };

    let config = OAuthClientConfig {
        client_metadata,
        keys: None,
        resolver: OAuthResolverConfig {
            did_resolver: CommonDidResolver::new(CommonDidResolverConfig {
                plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
                http_client: shared_http_client.clone(),
            }),
            handle_resolver: AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
                dns_txt_resolver: AtDnsTxtResolver{
                    http_client: http_client.clone(),
                },
                http_client: shared_http_client.clone(),
            }),
            authorization_server_metadata: Default::default(),
            protected_resource_metadata: Default::default(),
        },
        state_store,
        http_client,
    };

    let client_res = OAuthClient::new(config);
    let client = client_res.unwrap();

    client
}
