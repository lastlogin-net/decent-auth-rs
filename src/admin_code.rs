use std::collections::{BTreeMap};
use crate::{error,Params,DaHttpResponse};
use crate::{
    SESSION_PREFIX,SessionBuilder,IdType,
    get_return_target,HEADER_TMPL,FOOTER_TMPL,LOGIN_ADMIN_CODE_TMPL,
    CommonTemplateData,get_session,DaHttpRequest,Config,KvStore,
    create_session_cookie,generate_random_text,
};
use crate::kv;

pub fn handle_login<T: kv::Store>(req: &DaHttpRequest, kv_store: &KvStore<T>, params: &Params, config: &Config) -> error::Result<DaHttpResponse> {

    let admin_id = if let Some(admin_id) = &config.admin_id {
        admin_id
    }
    else {
        return Ok(DaHttpResponse::new(400, &format!("Invalid admin id")));
    };

    if let Some(code) = params.get("code") {
        if code == "" {
            return Ok(DaHttpResponse::new(400, &format!("Invalid code")));
        }

        let key = format!("/{}/{}/{}", config.storage_prefix, "pending_admin_codes", code);
        let _val: String = kv_store.get(&key)?;
        let _ = kv_store.delete(&key);

        let session_key = generate_random_text();
        let session_cookie = create_session_cookie(&config.storage_prefix, &session_key);

        // TODO: admin code logins might not be email IDs
        let session = SessionBuilder::new(IdType::Email, &admin_id)
            .build();

        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
        kv_store.set(&kv_session_key, session)?;

        let mut res = DaHttpResponse::new(303, &format!("{}/callback", config.path_prefix));

        let return_target = get_return_target(&req);

        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![return_target]),
            ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
        ]);

        return Ok(res);
    }
    else {

        let new_code = generate_random_text();
        let key = format!("/{}/{}/{}", config.storage_prefix, "pending_admin_codes", new_code);
        kv_store.set(&key, "fake-value")?;

        println!("Admin login code: {}", new_code);

        let session = get_session(&req, kv_store, config);

        let template = mustache::compile_str(LOGIN_ADMIN_CODE_TMPL)?;
        let data = CommonTemplateData{ 
            config,
            header: HEADER_TMPL,
            footer: FOOTER_TMPL,
            session,
            prefix: config.path_prefix.clone(),
            return_target: get_return_target(&req),
        };
        let body = template.render_to_string(&data)?;

        let mut res = DaHttpResponse::new(200, &body);
        res.headers = BTreeMap::from([
            ("Content-Type".to_string(), vec!["text/html".to_string()]),
        ]);

        return Ok(res);
    }
}
