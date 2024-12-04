use crate::{
    handle,DaHttpRequest,BTreeMap,get_session,Session,KvStore,
    Config,kv,
};

pub struct Server<T: kv::Store> {
    pub config: Config,
    kv_store: KvStore<T>,
}

impl<T: kv::Store> Server<T> {
    pub fn new(config: Config, kv_store: T) -> Self {
        Self{
            config,
            kv_store: KvStore{
                byte_kv: kv_store,
            },
        }
    }

    pub fn get_session(&self, in_headers: &http::HeaderMap) -> Option<Session> {

        let mut headers = BTreeMap::new();
        for (key, value) in in_headers {
            let val = value.to_str().unwrap().to_string();
            headers.insert(key.to_string(), vec![val]);
        }

        let req = DaHttpRequest{
            url: "".to_string(),
            method: Some("GET".to_string()),
            headers,
            body: "".to_string(),
        };

        get_session(&req, &self.kv_store, &self.config)
    }

    pub fn handle(&mut self, req: http::Request<bytes::Bytes>) -> http::Response<bytes::Bytes> {

        let mut host = None;
        let mut headers = BTreeMap::new();
        for (key, value) in req.headers() {
            let val = value.to_str().unwrap().to_string();
            if key == "host" {
                host = Some(val.clone());
            }
            headers.insert(key.to_string(), vec![val]);
        }

        let url = if let Some(query) = req.uri().query() {
            format!("http://{}{}?{}", host.unwrap_or_default(), req.uri().path(), query)
        }
        else {
            format!("http://{}{}", host.unwrap_or_default(), req.uri().path())
        };

        let da_req = DaHttpRequest{
            url,
            method: Some(req.method().as_str().to_string()),
            headers,
            body: std::str::from_utf8(req.body()).unwrap().to_string(),
        };

        let da_res = handle(da_req, &mut self.kv_store, &self.config).unwrap();

        let mut res_builder = http::Response::builder()
            .status(http::StatusCode::from_u16(da_res.code).unwrap());

        for (key, values) in da_res.headers {
            res_builder = res_builder.header(key, values[0].clone());
        }

        let res = res_builder.body(bytes::Bytes::from(da_res.body));

        res.unwrap()
    }
}