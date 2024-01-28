use chrono::{DateTime, Local};
use log::{error, info};
use network_device_logger::db::{AddrRecord, Database, Config};
use rtshark;
use std::fs;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;


fn main() {
    env_logger::init();

    let config: Config = Config::from_env();
    info!("loaded config -> {config:?}");

    let _ = fs::remove_file(&config.PCAP_FILE_PATH);

    loop {
        info!("connecting to database -> {}", &config.DATABASE_FILE_PATH);
        let db = Database::new(&config.DATABASE_FILE_PATH, &config.DATABASE_SEED_FILE_PATH);
        info!("database connection successful");

        info!("starting tshark on <{}>", &config.TSHARK_TARGET_INTERFACE);
        info!("tshark running for {} seconds", &config.TSHARK_RUN_DURATION);
        match run_tshark(
            &config.TSHARK_TARGET_INTERFACE,
            &config.PCAP_FILE_PATH,
            config.TSHARK_RUN_DURATION) {
            Err(message) => {
                error!("{}", message);
                return;
            }
            Ok(_) => {
                // skip
            }
        }
        info!("reading generated pcap file -> {}", config.PCAP_FILE_PATH);
        match extract_pcap(&config.PCAP_FILE_PATH) {
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
        let _ = fs::remove_file(&config.PCAP_FILE_PATH);

        info!("sleeping {} seconds", &config.SLEEP);
        sleep(Duration::from_secs(config.SLEEP));
    }
}

fn extract_pcap(pcap_path: &str) -> Result<Vec<AddrRecord>, String> {
    let mut addresses: Vec<AddrRecord> = Vec::new();
    let current_date: DateTime<Local> = Local::now();
    


    let builder = rtshark::RTSharkBuilder::builder().input_path(&pcap_path);
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

fn run_tshark(interface: &str, pcap_path: &str, duration: u64) -> Result<(), String> {
    let result = Command::new("tshark")
        .arg("-i")
        .arg(interface)
        .arg("-a")
        .arg(format!("duration:{}", duration))
        .arg("-w")
        .arg(pcap_path)
        .output()
        .expect("Failed to execute tshark command");

    match result.status.code() {
        Some(0) => return Ok(()),
        Some(code) => return Err(format!("tshark exited with {}", code)),
        None => return Err("Unknown error; no exit code".to_string()),
    }
}
