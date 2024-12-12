use std::collections::BTreeMap;
use std::sync::Arc;
use crate::{
    DaHttpRequest,DaHttpResponse,KvStore,Config,error,kv,Url,DaError,
    parse_params,Session,SESSION_PREFIX,generate_random_text,
};
use cookie::Cookie;

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

type DaOAuthClient<'a, T> = OAuthClient<AtKvStore<'a, T>,CommonDidResolver<AtHttpClient>,AtprotoHandleResolver<AtDnsTxtResolver,AtHttpClient>,AtHttpClient>;

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> 
where T: kv::Store,
{
    let rt = get_async_runtime();

    let client = get_client(req, kv_store, config);

    let redir_url = rt.block_on(async {

        let redir_url = client
            .authorize(
                String::from("https://bsky.social"),
                AuthorizeOptions {
                    scopes: vec![
                        Scope::Known(KnownScope::Atproto),
                        Scope::Known(KnownScope::TransitionGeneric)
                    ],
                    ..Default::default()
                }
            )
            .await.unwrap();

        redir_url
    });

    let mut res = DaHttpResponse::new(303, &format!("Redirect to {}", redir_url));
    res.headers = BTreeMap::from([
        ("Location".to_string(), vec![redir_url]),
    ]);

    Ok(res)
}

pub fn handle_callback<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

    let params = parse_params(&req).unwrap();

    let callback_params = CallbackParams{
        code: params.get("code").unwrap().to_string(),
        iss: Some(params.get("iss").unwrap().to_string()),
        state: Some(params.get("state").unwrap().to_string()),
    };

    let client = get_client(req, kv_store, config);

    let rt = get_async_runtime();
    let session = rt.block_on(async {
        let res = client.callback(callback_params).await.unwrap();

        let did_resolver = CommonDidResolver::new(CommonDidResolverConfig {
            plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
            http_client: Arc::new(AtHttpClient::default()),
        });

        let did_str = res.sub.clone();
        let did = Did::new(did_str).unwrap();
        let did_doc = did_resolver.resolve(&did).await.unwrap();

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

        session
    });

    let session_key = generate_random_text();
    let session_cookie = Cookie::build((format!("{}_session_key", config.storage_prefix), &session_key))
        .path("/")
        .secure(true)
        .http_only(true);

    let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
    kv_store.set(&kv_session_key, &session)?;

    let mut res = DaHttpResponse::new(303, "");
    res.headers = BTreeMap::from([
        ("Location".to_string(), vec!["/".to_string()]),
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
}

// TODO: actually implement
impl DnsTxtResolver for AtDnsTxtResolver {
    async fn resolve(
        &self,
        _query: &str,
    ) -> core::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        println!("dns here");
        Ok(vec![])
        //Ok(self.resolver.txt_lookup(query).await?.iter().map(|txt| txt.to_string()).collect())
    }
}


#[cfg(not(target_arch = "wasm32"))]
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
            let val = value.to_str().unwrap().to_string();
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
    type Error = DaError;

    async fn get(&self, key: &String) -> Result<Option<InternalStateData>, Self::Error> {
        let res = self.kv_store.get(key);
        Ok(Some(res.unwrap()))
    }

    async fn set(&self, key: String, value: InternalStateData) -> Result<(), Self::Error> {
        Ok(self.kv_store.set(&key, value).unwrap())
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
fn get_async_runtime() -> tokio::runtime::Runtime {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build().unwrap();
    rt
}

#[cfg(target_arch = "wasm32")]
fn get_async_runtime() -> tokio::runtime::Runtime {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build().unwrap();
    rt
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
                dns_txt_resolver: AtDnsTxtResolver{},
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
