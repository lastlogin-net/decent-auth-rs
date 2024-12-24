use std::{fmt};
use std::sync::Mutex;
use serde::{Serialize,Deserialize};
use std::collections::HashMap;

pub trait Store: Sync {
    fn get(&self, key: &str) -> Result<Vec<u8>, Error>;
    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), Error>;
    fn delete(&self, key: &str) -> Result<(), Error>;
    fn list(&self, prefix: &str) -> Result<Vec<String>, Error>;
}

#[derive(Debug,Serialize,Deserialize)]
pub struct Error {
    msg: String
}

impl Error {
    pub fn new(msg: &str) -> Self {
        Self{
            msg: msg.to_string(),
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {}", self.msg)
    }
}


pub struct KvStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl Store for KvStore {
    fn get(&self, key: &str) -> Result<Vec<u8>, Error> {

        let map = self.map.lock().map_err(|_| Error::new("Lock failed"))?;

        let value = &map.get(key).ok_or(Error::new("Fail"))?;

        //println!("kv get {}, {:?}", key, value);

        Ok(value.to_vec())
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        //println!("kv set {}, {:?}", key, value);

        let mut map = self.map.lock().map_err(|_| Error::new("Lock failed"))?;

        map.insert(key.to_string(), value);

        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        let mut map = self.map.lock().map_err(|_| Error::new("Lock failed"))?;

        map.remove(key);

        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, Error> {

        let map = self.map.lock().map_err(|_| Error::new("Lock failed"))?;

        let keys = map.iter()
            .filter(|(k,_v)| {
                k.starts_with(prefix)
            })
            .map(|(k,_v)| {
                k.clone()
            }).collect::<Vec<String>>();

        Ok(keys)
    }
}
