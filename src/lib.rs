use rusqlite::{Connection, Error, Result as RusqliteResult};
use std::fs;

pub mod db {
    use crate::get_db_connection;
    use chrono::{DateTime, Local};
    use dotenv::dotenv;
    use rlua::{Context, Error as LuaError, Lua, Result as LuaResult, UserData};
    use rusqlite::Connection;
    use std::{env, fs};
    #[derive(Debug, PartialEq)]
    pub struct AddrRecord {
        pub ip: String,
        pub mac: String,
        pub last_seen: DateTime<Local>,
    }

    impl UserData for AddrRecord {
        fn add_methods<'lua, T: rlua::prelude::LuaUserDataMethods<'lua, Self>>(_methods: &mut T) {
            _methods.add_method("ip", |_, this, _: ()| Ok(this.ip.clone()));
            _methods.add_method("mac", |_, this, _: ()| Ok(this.mac.clone()));
        }
    }

    pub enum Event {
        NewInternetProtocolAddress,
        HardwareChange,
    }

    impl Event {
        fn to_lua(&self) -> String {
            match self {
                Event::NewInternetProtocolAddress => "NewInternetProtocolAddress".to_owned(),
                Event::HardwareChange => "HardwareChange".to_owned(),
            }
        }
    }

    pub struct Database {
        conn: Connection,
    }

    impl Database {
        pub fn new(database_path: &str, schema_path: &str) -> Database {
            let conn =
                get_db_connection(database_path.to_string(), schema_path.to_string()).unwrap();
            Database { conn }
        }

        pub fn get_all_records(&self) -> Result<Vec<AddrRecord>, rusqlite::Error> {
            let mut statement = self
                .conn
                .prepare("SELECT * FROM addrs ORDER BY last_seen DESC;")?;
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
            let statement = self
                .conn
                .prepare("INSERT OR REPLACE INTO addrs (ip, mac, last_seen) VALUES (?, ?, ?)");
            let _ = statement.unwrap().execute([
                addr_record.ip,
                addr_record.mac,
                addr_record
                    .last_seen
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
            ]);
        }

        pub fn clear_all(&self) {
            let statement = self.conn.prepare("DELETE FROM addrs");
            let _ = statement.unwrap().execute([]);
        }
    }

    #[allow(non_snake_case)]
    #[derive(Debug)]
    pub struct Config {
        pub DATABASE_FILE_PATH: String,
        pub DATABASE_SEED_FILE_PATH: String,
        pub PCAP_FILE_PATH: String,
        pub TSHARK_RUN_DURATION: u64,
        pub TSHARK_TARGET_INTERFACE: String,
        pub SLEEP: u64,
    }

    impl Config {
        pub fn from_env() -> Config {
            dotenv().ok();

            Config {
                DATABASE_FILE_PATH: env::var("DATABASE_FILE_PATH")
                    .expect("environment variable DATABASE_FILE must be set"),
                DATABASE_SEED_FILE_PATH: env::var("DATABASE_SEED_FILE_PATH")
                    .expect("environment variable DATABASE_SEED_FILE_PATH must be set"),
                PCAP_FILE_PATH: env::var("PCAP_FILE_PATH")
                    .expect("environment variable PCAP_FILE_PATH must be set"),
                TSHARK_TARGET_INTERFACE: env::var("TSHARK_TARGET_INTERFACE")
                    .expect("environment variable TSHARK_TARGET_INTERFACE must be set"),
                TSHARK_RUN_DURATION: env::var("TSHARK_RUN_DURATION")
                    .expect("environment variable TSHARK_RUN_DURATION must be set")
                    .parse::<u64>()
                    .expect("environment variable TSHARK_RUN_DURATION could not be cast to u64"),
                SLEEP: env::var("SLEEP")
                    .expect("environment variable SLEEP must be set")
                    .parse::<u64>()
                    .expect("environment variable SLEEP could not be cast to u64"),
            }
        }
    }
    pub fn to_time_since(dt: DateTime<Local>) -> String {
        let duration = Local::now().signed_duration_since(dt);
        match duration {
            d if d.num_days() > 0 => format!("{} days ago", d.num_days()),
            h if h.num_hours() > 0 => format!("{} hours ago", h.num_hours()),
            m if m.num_minutes() > 0 => format!("{} minutes ago", m.num_minutes()),
            _ => format!("Recently"),
        }
    }

    pub fn lua_exec(addr_record: AddrRecord, event: Event, lua_file_path: String) -> LuaResult<()> {
        let lua = Lua::new();
        lua.context(|ctx| {
            let globals = ctx.globals();
            globals.set("addrRecord", addr_record)?;

            globals.set("event", event.to_lua())?;
            Ok(())
        })?;

        lua.context(|ctx| {
            let _ = ctx
                .load(&fs::read_to_string(&lua_file_path).expect("unable to read lua file"))
                .exec();
        });

        Ok(())
    }
}

fn get_db_connection(file: String, schema_path: String) -> RusqliteResult<Connection, Error> {
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

fn seed(conn: &Connection, schema_path: String) -> Result<(), ()> {
    let sql = fs::read_to_string(schema_path);
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
