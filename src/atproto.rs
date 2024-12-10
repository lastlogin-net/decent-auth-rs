use std::collections::BTreeMap;
use std::sync::Arc;
use crate::{DaHttpRequest,DaHttpResponse,KvStore,Config,error,kv,Url,DaError};

use atrium_xrpc::HttpClient;
use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL};
use atrium_identity::handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig, DnsTxtResolver};
use atrium_oauth_client::store::{SimpleStore,state::{StateStore,InternalStateData}};
use atrium_oauth_client::{
    AuthorizeOptions, KnownScope, OAuthClient,
    OAuthClientConfig, OAuthResolverConfig, Scope, GrantType, AuthMethod,
    AtprotoClientMetadata, OAuthClientMetadata,
};

pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> 
where T: kv::Store,
{

    let parsed_url = Url::parse(&req.url)?; 
    let host = parsed_url.host().ok_or(DaError::new("Failed to parse host"))?;

    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();

    let shared_http_client = Arc::new(AtHttpClient::default());
    let http_client = AtHttpClient::default();

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

    let state_store = AtKvStore{
        kv_store,
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
    let client = client_res?;

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

pub fn handle_callback<T: kv::Store>(_req: &DaHttpRequest, _kv_store: &KvStore<T>, _config: &Config) -> error::Result<DaHttpResponse> {
    Ok(DaHttpResponse::new(200, "Hi there"))
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

pub struct AtHttpClient {
}

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
        self.kv_store.get(key).unwrap()
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
