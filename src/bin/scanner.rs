use chrono::{DateTime, Local};
use log::{error, info};
use network_device_logger::db::{AddrRecord, Database};
use rtshark;
use std::fs;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

const DATABASE_FILE_PATH: &str = "./addrs.sqlite3";
const DATABSE_SEED_FILE_PATH: &str = "./database.sql";
const PCAP_FILE_PATH: &str = "./memfs/scan.pcap";
const TSHARK_RUN_DURATION: u16 = 30;
const TSHARK_TARGET_INTERFACE: &str = "enp0s31f6";
const SLEEP: u64 = 30;

fn main() {
    let _ = fs::remove_file(PCAP_FILE_PATH);
    env_logger::init();

    loop {
        info!("connecting to database -> {}", DATABASE_FILE_PATH);
        let db = Database::new(DATABASE_FILE_PATH, DATABSE_SEED_FILE_PATH);
        info!("database connection successful");

        info!("starting tshark on <{}>", TSHARK_TARGET_INTERFACE);
        info!("tshark running for {} seconds", TSHARK_RUN_DURATION);
        match run_tshark(TSHARK_TARGET_INTERFACE.to_string(), TSHARK_RUN_DURATION) {
            Err(message) => {
                error!("{}", message);
                return;
            }
            Ok(_) => {
                // skip
            }
        }
        info!("reading generated pcap file -> {}", PCAP_FILE_PATH);
        match extract_pcap() {
            Err(message) => {
                error!("{}", message)
            }
            Ok(results) => {
                for addr in results {
                    info!("{:?}", addr);
                    db.insert(addr);
                }
            }
        }
        info!("deleting generated pcap file...");
        let _ = fs::remove_file(PCAP_FILE_PATH);

        info!("sleeping {} seconds", SLEEP);
        sleep(Duration::from_secs(SLEEP));
    }
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
        if ip_addr.is_empty() || mac_addr.is_empty() {
            continue;
        }

        let addr_record = AddrRecord {
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

fn run_tshark(interface: String, duration: u16) -> Result<(), String> {
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
