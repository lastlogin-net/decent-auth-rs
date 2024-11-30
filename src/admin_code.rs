use std::collections::{BTreeMap};
use crate::{error,Params,DaHttpResponse};
use crate::{
    info,kv_read_json,kv_write_json,CsrfToken,SESSION_PREFIX,Session,
    Cookie,get_return_target,HEADER_TMPL,FOOTER_TMPL,LOGIN_ADMIN_CODE_TMPL,
    CommonTemplateData,get_session,DaHttpRequest,Config
};

pub fn handle_login(req: &DaHttpRequest, params: &Params, config: &Config) -> error::Result<DaHttpResponse> {

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
        let _val: String = kv_read_json(&key)?;

        let session_key = CsrfToken::new_random().secret().to_string();
        let session_cookie = Cookie::build((format!("{}_session_key", config.storage_prefix), &session_key))
            .path("/")
            .secure(true)
            .http_only(true);

        let session = Session{
            id_type: "email".to_string(),
            id: admin_id.to_string(),
        };

        let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
        kv_write_json(&kv_session_key, session)?;

        let mut res = DaHttpResponse::new(303, &format!("{}/callback", config.path_prefix));

        let return_target = get_return_target(&req);

        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![return_target]),
            ("Set-Cookie".to_string(), vec![session_cookie.to_string()])
        ]);

        return Ok(res);
    }
    else {

        let new_code = CsrfToken::new_random().secret().to_string();
        let key = format!("/{}/{}/{}", config.storage_prefix, "pending_admin_codes", new_code);
        kv_write_json(&key, "fake-value")?;

        info!("Admin login code: {}", new_code);

        let session = get_session(&req, config);

        let template = mustache::compile_str(LOGIN_ADMIN_CODE_TMPL)?;
        let data = CommonTemplateData{ 
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
