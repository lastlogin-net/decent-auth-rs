use decentauth::kv::{Error,Store};
use std::sync::Mutex;

//impl From<rusqlite::Error> for Error {
//    fn from(e: rusqlite::Error) -> Error {
//        Error{ msg: format!("rusqlite error: {}", e) }
//    }
//}

pub struct KvStore {
    db: Mutex<rusqlite::Connection>,
    table_name: String,
}

impl KvStore {

    pub fn new() -> Result<Self, Error> {

        let db = rusqlite::Connection::open("db.sqlite")
            .map_err(|e| Error::new(&e.to_string()))?;

        let table_name = "kv";

        db.execute(
            &format!("CREATE TABLE IF NOT EXISTS {}(
                    key TEXT NOT NULL PRIMARY KEY,
                    value BLOB NOT NULL
            );", table_name),
            (),
        ).map_err(|e| Error::new(&e.to_string()))?;

        Ok(Self{
            db: Mutex::new(db),
            table_name: table_name.to_string(),
        })
    }
}

impl Store for KvStore {
    fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        let db = self.db.lock().map_err(|_| Error::new("Lock failed"))?;

        let value = db.query_row(
            &format!("SELECT value FROM {} WHERE key = ?", self.table_name),
            (key,),
            |row| row.get(0),
        ).map_err(|e| Error::new(&e.to_string()))?;

        Ok(value)
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        let db = self.db.lock().map_err(|_| Error::new("Lock failed"))?;

        db.execute(
            &format!("INSERT OR REPLACE INTO {}(key, value) VALUES(?, ?)", self.table_name),
            (key, value),
        ).map_err(|e| Error::new(&e.to_string()))?;

        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        let db = self.db.lock().map_err(|_| Error::new("Lock failed"))?;

        db.execute(
            &format!("DELETE FROM {} WHERE key = ?", self.table_name),
            (key,),
        ).map_err(|e| Error::new(&e.to_string()))?;

        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>, Error> {

        let db = self.db.lock().map_err(|_| Error::new("Lock failed"))?;

        let mut stmt = db.prepare(
            &format!("SELECT key FROM {} WHERE key GLOB ? || '*'", self.table_name),
        ).map_err(|e| Error::new(&e.to_string()))?;

        let mut rows = stmt.query((prefix,))
            .map_err(|e| Error::new(&e.to_string()))?;

        let mut keys = Vec::new();

        while let Some(row) = rows.next().map_err(|e| Error::new(&e.to_string()))? {
            keys.push(row.get(0).map_err(|e| Error::new(&e.to_string()))?);
        }

        Ok(keys)
    }
}
