use rusqlite;
use rusqlite::{Connection, Result as rusqliteResult};
use std::fs;
use std::process::Command;

const DATABASE_FILE_PATH: &str = "./addrs.sqlite3";
const DATABSE_SEED_FILE_PATH: &str = "./database.sql";

fn main() {
    // let interface = String::from("enp0s31f6");
    // let r = run_tshark(interface, 10);
    // if r.is_err(){
    //     eprintln!("failed: {:?}", r.unwrap())
    // }
    //
    // let conn = get_db_connection();
    // if conn.is_err() {
        // println!("database is not seeded")
    // }
    println!("meow")
}

fn get_db_connection() -> rusqliteResult<Connection, rusqlite::Error> {
    let conn = Connection::open(DATABASE_FILE_PATH)?;
    match is_seeded(&conn) {
        true => Ok(conn),
        false => {
            let _ = seed(&conn);
            Ok(conn)
        }
    }
}

fn is_seeded(conn: &Connection) -> bool {
    let sql = conn.prepare("SELECT COUNT(*) FROM addrs");
    let result = sql.unwrap().query_row([], |row| row.get::<_, i64>(0));

    match result {
        Err(e) => {
            println!("{}", e);
            return false;
        },

        _ => return true
    }
}

fn seed(conn: &Connection) -> Result<(), ()> {
    let sql = fs::read_to_string(DATABSE_SEED_FILE_PATH);
    match sql {
        Ok(sql_string) => {
            println!("{}", &sql_string);
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

fn run_tshark(interface: String, duration: u8) -> Result<(), String> {
    let result = Command::new("tshark")
        .arg("-i")
        .arg(interface) // Replace with your actual interface, e.g., eth0
        .arg("-a")
        .arg(format!("duration:{}", duration))
        .arg("-w")
        .arg("./scan.pcap") // Replace with your actual file path
        .output()
        .expect("Failed to execute command");

    match result.status.code() {
        Some(0) => return Ok(()),
        Some(code) => return Err(format!("tshark exited with {}", code)),
        None => return Err("Unknown error; no exit code".to_string()),
    }
}
