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
    source: CaptureSource,
}

#[derive(clap::Subcommand)]
enum CaptureSource {
    Device { name: String },
    File { path: PathBuf },
}

fn handle_packet(packet: Packet) -> Result<Beacon> {
    // let signal = get_signal(&packet.data)?.context("Missing signal")?;
    let radiotap = Radiotap::from_bytes(&packet.data)?;
    let payload = &packet.data[radiotap.header.length..];
    let beacon = beacon::parse(payload)?.context("not a beacon")?;

    // let elems: Vec<_> = beacon
    //     .elements
    //     .into_iter()
    //     .filter(|(k, v)| *k != 0)
    //     .collect();
    // println!("{:?} {} {ssid:?}", elems, beacon.source);
    // println!("{:?}", beacon.elements);

    Ok(beacon)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut pcap: Capture<dyn Activated> = match cli.source {
        CaptureSource::Device { name } => {
            let device = Device::list()?
                .into_iter()
                .find(|x| x.name == name)
                .context("failed to find a device with that name")?;
            Capture::from_device(device)?
                .immediate_mode(true)
                .open()?
                .into()
        }
        CaptureSource::File { path } => Capture::from_file(path)?.into(),
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

    eprintln!(
        "Beacons with stable fingerprints: {}",
        history.len() - bad.len()
    );
    eprintln!("Beacons with unstable fingreprints: {}", bad.len());

    let mut all = BTreeSet::new();
    for (_, v) in &history {
        all.insert(v);
    }
    eprintln!("Unique fingerprints: {}", all.len());

    let mut all: BTreeSet<Vec<_>> = BTreeSet::new();
    for (_, v) in history {
        for (k, v) in &v {
            println!("{k}");
        }
        let v = v.into_iter().filter(|(k, _)| *k != 0).collect();
        // println!("{v:?}");
        all.insert(v);
    }
    eprintln!("Unique fingerprints (excluding SSID): {}", all.len());

    Ok(())
}
