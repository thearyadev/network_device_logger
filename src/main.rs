use chrono::{DateTime, Local};
use rtshark;
use rusqlite;
use rusqlite::{Connection, Result as rusqliteResult};
use std::fs;
use std::ops::Add;
use std::process::Command;

const DATABASE_FILE_PATH: &str = "./addrs.sqlite3";
const DATABSE_SEED_FILE_PATH: &str = "./database.sql";
const PCAP_FILE_PATH: &str = "./memfs/scan.pcap";
const TSHARK_RUN_DURATION: u8 = 30;
const TSHARK_TARGET_INTERFACE: &str = "enp0s31f6";

#[derive(Debug, PartialEq)]
struct AddrRecord {
    id: i32,
    ip: String,
    mac: String,
    last_seen: DateTime<Local>,
}

fn main() {
    let r = run_tshark(TSHARK_TARGET_INTERFACE.to_string(), TSHARK_RUN_DURATION);
    if r.is_err() {
        eprintln!("failed: {:?}", r.unwrap())
    }

    let result = extract_pcap();
    for addr in result.unwrap() {
        println!("{addr:?}");
    }

    fs::remove_file(PCAP_FILE_PATH).expect("file del no worki")
}

fn extract_pcap() -> Result<Vec<AddrRecord>, String> {
    let mut addresses: Vec<AddrRecord> = Vec::new();
    let current_date: DateTime<Local> = Local::now();

    let builder = rtshark::RTSharkBuilder::builder().input_path(PCAP_FILE_PATH);
    let mut rtshark = builder
        .spawn()
        .unwrap_or_else(|e| panic!("error starting tshark {e}"));

    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing tshark output: {e}");
        None
    }) {
        let mut ip_addr = String::new();
        let mut mac_addr = String::new();

        for layer in packet {
            if layer.name() == "ip" {
                if let Some(ip_metadata) = layer.metadata("ip.addr") {
                    ip_addr = ip_metadata.value().to_string();
                }
            } else if layer.name() == "eth" {
                if let Some(eth_metadata) = layer.metadata("eth.src") {
                    mac_addr = eth_metadata.value().to_string();
                }
            }
        }
        if ip_addr.is_empty() || mac_addr.is_empty(){
            continue
        }



        let addr_record = AddrRecord {
            id: 0,
            ip: ip_addr,
            mac: mac_addr,
            last_seen: current_date,
        };
        if !addresses.contains(&addr_record) {
            addresses.push(addr_record)
        }
    }
    Ok(addresses)
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

fn insert(conn: &Connection, addr_record: AddrRecord) {
    let statement = conn.prepare("INSERT INTO addrs (ip, mac, last_seen) VALUES (?, ?, ?)");
    let _ = statement.unwrap().execute([
        addr_record.ip,
        addr_record.mac,
        addr_record
            .last_seen
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
    ]);
}

fn retrieve(conn: &Connection) -> Result<Vec<AddrRecord>, rusqlite::Error> {
    let mut statement = conn.prepare("SELECT * FROM addrs;")?;
    let rows = statement.query_map([], |row| {
        Ok(AddrRecord {
            id: row.get(0)?,
            ip: row.get(1)?,
            mac: row.get(2)?,
            last_seen: row.get(3)?,
        })
    })?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    Ok(records)
}

fn is_seeded(conn: &Connection) -> bool {
    let sql = conn.prepare("SELECT COUNT(*) FROM addrs");
    let result = sql.unwrap().query_row([], |row| row.get::<_, i64>(0));

    match result {
        Err(e) => {
            println!("{}", e);
            return false;
        }

        _ => return true,
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
        .arg(PCAP_FILE_PATH) // Replace with your actual file path
        .output()
        .expect("Failed to execute tshark command");

    match result.status.code() {
        Some(0) => return Ok(()),
        Some(code) => return Err(format!("tshark exited with {}", code)),
        None => return Err("Unknown error; no exit code".to_string()),
    }
}
