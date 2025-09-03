use crate::{
    generate_random_text,Config,SESSION_PREFIX,CODES_PREFIX,KvStore,kv,IdType,SessionBuilder,EMAIL_STR,
};
use serde::{Serialize,Deserialize};

#[derive(Debug,Deserialize)]
pub struct CreateSessionRequest {
    id: String,
    id_type: String,
}

#[derive(Debug,Serialize)]
pub struct CreateSessionResult {
    token: String,
    code: String,
}

pub fn create_session<T: kv::Store>(kv_store: &KvStore<T>, config: &Config, req: &CreateSessionRequest) -> Result<CreateSessionResult, kv::Error> {

    // TODO: admin code logins might not be email IDs
    let id_type = match &req.id_type[..] {
        EMAIL_STR => IdType::Email,
        &_ => todo!(),
    };

    let session = SessionBuilder::new(id_type, &req.id).build();

    let session_key = generate_random_text();
    let kv_session_key = format!("/{}/{}/{}", config.storage_prefix, SESSION_PREFIX, &session_key);
    kv_store.set(&kv_session_key, session)?;

    let code_key = generate_random_text();
    let kv_code_key = format!("/{}/{}/{}", config.storage_prefix, CODES_PREFIX, &code_key);
    kv_store.set(&kv_code_key, &session_key)?;

    Ok(CreateSessionResult{
        token: session_key,
        code: code_key,
    })
}
