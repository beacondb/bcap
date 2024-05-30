use beacon::Beacon;
use clap::Parser;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use anyhow::{Context, Result};
use pcap::{Activated, Capture, Device, Packet};
use radiotap::Radiotap;

mod beacon;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    File { path: PathBuf },
}

fn handle_packet(packet: Packet) -> Result<Beacon> {
    let radiotap = Radiotap::from_bytes(&packet.data)?;
    let payload = &packet.data[radiotap.header.length..];
    let beacon = beacon::parse(payload)?.context("not a beacon")?;
    Ok(beacon)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut pcap: Capture<dyn Activated> = match cli.command {
        // Command::Device { name } => {
        //     let device = Device::list()?
        //         .into_iter()
        //         .find(|x| x.name == name)
        //         .context("failed to find a device with that name")?;
        //     Capture::from_device(device)?
        //         .immediate_mode(true)
        //         .open()?
        //         .into()
        // }
        Command::File { path } => Capture::from_file(path)?.into(),
    };

    let mut history = BTreeMap::new();
    let mut bad = BTreeSet::new();
    loop {
        let p = match pcap.next_packet() {
            Err(pcap::Error::NoMorePackets) => break,
            x => x?,
        };
        let b = match handle_packet(p) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{e}");
                continue;
            }
        };

        let a = b.source;
        if let Some(previous) = history.insert(a, b.elements) {
            let new = history.get(&a).unwrap();
            if &previous != history.get(&a).unwrap() {
                bad.insert(a);

                let s = previous
                    .iter()
                    .find(|x| x.0 == 0)
                    .map(|x| String::from_utf8_lossy(&x.1));
                // println!("{a:?} {s:?}\n{previous:?}\n{new:?}\n\n");
            }
        }
    }

    eprintln!("Stable fingerprints: {}", history.len() - bad.len());
    eprintln!("Unstable fingerprints: {}", bad.len());
    let all = BTreeSet::from_iter(history.iter().map(|x| x.1));
    eprintln!("Unique fingerprints (excl bssid): {}", all.len());

    // for (k, v) in &history {
    //     let mut beacon_bytes = Vec::from(k);
    //     for (k, v) in v {
    //         beacon_bytes.push(*k);
    //         beacon_bytes.extend(v);
    //     }
    //     let hash = sha256::digest(&beacon_bytes);
    // }

    Ok(())
}
