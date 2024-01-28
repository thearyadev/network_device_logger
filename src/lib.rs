use rusqlite::{Connection, Error, Result as RusqliteResult};
use std::fs;

pub mod db {
    use crate::get_db_connection;
    use chrono::{DateTime, Local};
    use rusqlite::Connection;
    #[derive(Debug, PartialEq)]
    pub struct AddrRecord {
        pub ip: String,
        pub mac: String,
        pub last_seen: DateTime<Local>,
    }

    pub struct Database {
        conn: Connection,
    }

    impl Database {
        pub fn new(database_path: &str, schema_path: &str) -> Database {
            let conn = get_db_connection(database_path.to_string(), schema_path).unwrap();
            Database { conn }
        }

        pub fn get_all_records(&self) -> Result<Vec<AddrRecord>, rusqlite::Error> {
            let mut statement = self.conn.prepare("SELECT * FROM addrs;")?;
            let rows = statement.query_map([], |row| {
                Ok(AddrRecord {
                    ip: row.get(0)?,
                    mac: row.get(1)?,
                    last_seen: row.get(2)?,
                })
            })?;

            let mut records = Vec::new();
            for row in rows {
                records.push(row?);
            }
            Ok(records)
        }

        pub fn insert(&self, addr_record: AddrRecord) {
            let statement =
                self.conn.prepare("INSERT OR REPLACE INTO addrs (ip, mac, last_seen) VALUES (?, ?, ?)");
            let _ = statement.unwrap().execute([
                addr_record.ip,
                addr_record.mac,
                addr_record
                    .last_seen
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
            ]);
        }
    }
}

fn get_db_connection(file: String, schema_path: &str) -> RusqliteResult<Connection, Error> {
    let conn = Connection::open(file)?;
    match is_seeded(&conn) {
        true => Ok(conn),
        false => {
            let _ = seed(&conn, schema_path);
            Ok(conn)
        }
    }
}

fn is_seeded(conn: &Connection) -> bool {
    let result = conn.prepare("SELECT COUNT(*) FROM addrs");

    match result {
        Err(_) => {
            return false;
        }
        Ok(_) => return true,
    }
}

fn seed(conn: &Connection, schema_path: &str) -> Result<(), ()> {
    let sql = fs::read_to_string(schema_path.to_string());
    match sql {
        Ok(sql_string) => {
            let database_seed_result = conn.execute(&sql_string, []);
            database_seed_result.unwrap();

            is_seeded(&conn);
            if !is_seeded(&conn) {
                panic!("Unable to seed database. Seed did not run correctly.")
            }
            Ok(())
        }
        Err(_) => {
            panic!("Unable to seed database. Permissions may be incorrectly set.")
        }
    }
}
