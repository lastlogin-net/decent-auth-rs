use std::collections::{BTreeMap};
use crate::{error,Params,DaHttpResponse};
use crate::{webfinger};

pub fn handle_login(params: &Params, path_prefix: &str) -> error::Result<DaHttpResponse> {

    if let Some(fediverse_handle) = params.get("handle") {
        if fediverse_handle == "" || !fediverse_handle.starts_with("@") {
            return Ok(DaHttpResponse::new(400, &format!("Invalid Fediverse handle '{fediverse_handle}'")));
        }

        webfinger::resolve(&fediverse_handle[1..])?;
    }
    else {
        let mut res = DaHttpResponse::new(303, "");
        res.headers = BTreeMap::from([
            ("Location".to_string(), vec![format!("{}/login-fediverse", path_prefix)]),
        ]);
        return Ok(res);
    }

    Ok(DaHttpResponse::new(200, "Hi there"))
}
