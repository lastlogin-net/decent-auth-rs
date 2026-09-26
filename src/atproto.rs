use std::collections::{HashMap,BTreeMap};
use std::sync::Arc;
use crate::{
    DaHttpRequest,DaHttpResponse,KvStore,Config,error,kv,DaError,
    parse_params,Session,SESSION_PREFIX,generate_random_text, get_return_target,
    create_session_cookie,SessionBuilder,IdType,template,Templater,get_host,
};
use serde::Deserialize;

use atrium_xrpc::HttpClient;
use atrium_api::{agent::SessionManager, types::string::Did};
use atrium_common::{resolver::Resolver, store::Store};
use atrium_identity::did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL};
use atrium_identity::handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig, DnsTxtResolver};
use atrium_oauth::store::{session::MemorySessionStore, state::{StateStore, InternalStateData}};
use atrium_oauth::{
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

type DaOAuthClient<T> = OAuthClient<AtKvStore<T>, MemorySessionStore, CommonDidResolver<AtHttpClient>, AtprotoHandleResolver<AtDnsTxtResolver, AtHttpClient>, AtHttpClient>;


pub fn handle_login<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config, templater: &Templater) -> error::Result<DaHttpResponse> 
where T: kv::Store,
{
    let params = parse_params(&req).unwrap_or(HashMap::new());

    if let Some(handle_or_server) = params.get("handle_or_server") {
        let rt = get_async_runtime()?;

        let client = get_client(req, kv_store, config)?;

        let redir_res: Result<String, atrium_oauth::Error> = rt.block_on(async {

            client.authorize(
                handle_or_server,
                AuthorizeOptions {
                    scopes: vec![Scope::Known(KnownScope::Atproto)],
                    // Upstream keeps this app state with its own random OAuth nonce.
                    state: Some(get_return_target(req)),
                    ..Default::default()
                },
            ).await
        });

        let redir_url = redir_res?;

        let mut res = DaHttpResponse::new(303, &format!("Redirect to {}", redir_url));
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![redir_url]),
        ]);

        Ok(res)
    }
    else {
        let data = template::CommonData{
            config,
            return_target: get_return_target(&req),
        };
        let body = templater.render_atproto_page(&data)?;

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

    let client = get_client(req, kv_store, config)?;

    let rt = get_async_runtime()?;
    let session_res: Result<(Session, String), atrium_oauth::Error> = rt.block_on(async {
        let (res, return_target) = client.callback(callback_params).await?;
        let return_target = return_target.ok_or_else(||
            atrium_oauth::Error::Callback("Missing application state".to_string())
        )?;

        let did_resolver = CommonDidResolver::new(CommonDidResolverConfig {
            plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
            http_client: Arc::new(AtHttpClient::default()),
        });

        let did_str = res.did().await.ok_or_else(||
            atrium_oauth::Error::Callback("Missing session DID".to_string())
        )?.to_string();
        let did = Did::new(did_str)
            .map_err(|_e| atrium_oauth::Error::Callback("Failed to create DID".to_string()))?;
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

        let session = SessionBuilder::new(IdType::AtProto, &id)
            .build();

        Ok((session, return_target))
    });

    let (session, return_target) = session_res?;

    let session_key = generate_random_text();
    let session_cookie = create_session_cookie(&config.storage_prefix, &session_key);

    let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
    kv_store.set(&kv_session_key, &session)?;

    let mut res = DaHttpResponse::new(303, "");
    res.headers = BTreeMap::from([
        ("Location".to_string(), vec![return_target]),
        ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
    ]);

    Ok(res)
}

pub fn handle_client_metadata<T: kv::Store>(req: &DaHttpRequest, _kv_store: &KvStore<T>, config: &Config) -> error::Result<DaHttpResponse> {

    let host = get_host(req, config)?;
    let root_uri = format!("https://{}", host);
    let meta_uri = format!("{}{}/atproto-client-metadata.json", root_uri, config.path_prefix);
    let redirect_uri = format!("{}{}/atproto-callback", root_uri, config.path_prefix);

    let meta = OAuthClientMetadata {
        client_id: meta_uri,
        client_uri: Some(root_uri),
        redirect_uris: vec![redirect_uri],
        token_endpoint_auth_method: Some("none".to_string()),
        grant_types: Some(vec!["authorization_code".to_string()]),
        scope: Some("atproto".to_string()),
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

struct AtKvStore<T: kv::Store> {
    byte_kv: Arc<T>,
    prefix: String,
}

impl<T: kv::Store> AtKvStore<T> {
    fn key(&self, state: &str) -> String {
        format!("{}{state}", self.prefix)
    }
}

impl<T: kv::Store> StateStore for AtKvStore<T> {}

impl<T: kv::Store> Store<String, InternalStateData> for AtKvStore<T> {
    type Error = kv::Error;

    async fn get(&self, key: &String) -> Result<Option<InternalStateData>, Self::Error> {
        let key = self.key(key);
        // Our KV trait has no get-optional operation. Check for an exact key
        // before reading; an unrelated key sharing the prefix is not a hit.
        if !self.byte_kv.list(&key)?.iter().any(|item| item == &key) {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&self.byte_kv.get(&key)?)?))
    }

    async fn set(&self, key: String, value: InternalStateData) -> Result<(), Self::Error> {
        self.byte_kv.set(&self.key(&key), serde_json::to_vec(&value)?)
    }

    async fn del(&self, key: &String) -> Result<(), Self::Error> {
        self.byte_kv.delete(&self.key(key))
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        for key in self.byte_kv.list(&self.prefix)? {
            self.byte_kv.delete(&key)?;
        }
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

fn get_client<T>(req: &DaHttpRequest, kv_store: &KvStore<T>, config: &Config) -> error::Result<DaOAuthClient<T>>
where T: kv::Store,
{
    let host = get_host(req, config)?;

    let shared_http_client = Arc::new(AtHttpClient::default());
    let http_client = AtHttpClient::default();

    let state_store = AtKvStore {
        byte_kv: Arc::clone(&kv_store.byte_kv),
        prefix: format!("/{}/atproto_oauth_state/", config.storage_prefix),
    };

    let root_uri = format!("https://{}", host);
    let meta_uri = format!("{}{}/atproto-client-metadata.json", root_uri, config.path_prefix);
    let redirect_uri = format!("{}{}/atproto-callback", root_uri, config.path_prefix);

    let client_metadata = AtprotoClientMetadata {
        client_id: meta_uri,
        client_uri: Some(root_uri),
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
        // DecentAuth currently uses the ATProto OAuth session only to obtain
        // the DID at login; it does not retain the upstream access tokens.
        session_store: MemorySessionStore::default(),
        http_client,
    };

    let client_res = OAuthClient::new(config);
    let client = client_res?;

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_store(backend: Arc<kv::KvStore>, prefix: &str) -> AtKvStore<kv::KvStore> {
        AtKvStore { byte_kv: backend, prefix: prefix.to_string() }
    }

    #[tokio::test]
    async fn oauth_state_survives_a_new_store_and_is_deleted_after_use() {
        // State and app state must survive the login/callback request boundary.
        let backend = Arc::new(kv::KvStore::default());
        let store = state_store(Arc::clone(&backend), "/test/atproto_oauth_state/");
        let value: InternalStateData = serde_json::from_str(r#"{
            "iss":"https://example.com", "verifier":"verifier", "app_state":"/welcome",
            "dpop_key": {"kty":"EC", "crv":"P-256",
                "x":"NIRNgPVAwnVNzN5g2Ik2IMghWcjnBOGo9B-lKXSSXFs",
                "y":"iWF-Of43XoSTZxcadO9KWdPTjiCoviSztYw7aMtZZMc",
                "d":"9MuCYfKK4hf95p_VRj6cxKJwORTgvEU3vynfmSgFH2M"}
        }"#).unwrap();
        store.set("nonce".to_string(), value.clone()).await.unwrap();
        store.set("nonce-other".to_string(), value.clone()).await.unwrap();

        let callback_store = state_store(Arc::clone(&backend), "/test/atproto_oauth_state/");
        assert_eq!(callback_store.get(&"nonce".to_string()).await.unwrap(), Some(value.clone()));
        assert_eq!(callback_store.get(&"missing".to_string()).await.unwrap(), None);
        callback_store.del(&"nonce".to_string()).await.unwrap();
        assert_eq!(store.get(&"nonce".to_string()).await.unwrap(), None);
        assert_eq!(store.get(&"nonce-other".to_string()).await.unwrap(), Some(value.clone()));

        let other = state_store(Arc::clone(&backend), "/other/atproto_oauth_state/");
        other.set("nonce-other".to_string(), value).await.unwrap();
        store.clear().await.unwrap();
        assert!(store.get(&"nonce-other".to_string()).await.unwrap().is_none());
        assert!(other.get(&"nonce-other".to_string()).await.unwrap().is_some());
    }
}
