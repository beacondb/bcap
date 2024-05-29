use anyhow::Result;
use libwifi::Addresses;
use libwifi::{parse_frame_control, parse_management_header, FrameSubType};
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u64, u8};
use nom::sequence::tuple;

#[derive(Debug)]
pub struct Beacon {
    pub source: [u8; 6],
    // cap_timestamp_us: u64,
    // ap_timestamp_us: u64,
    pub elements: Vec<(u8, Vec<u8>)>,
}

// modified from libwifi::parse_beacon, libwifi::parse_station_info
pub fn parse(input: &[u8]) -> Result<Option<Beacon>, libwifi::error::Error> {
    let (input, frame_control) = parse_frame_control(&input)?;

    match frame_control.frame_subtype {
        FrameSubType::Beacon => (),
        _ => return Ok(None),
    };

    let (input, header) = parse_management_header(frame_control, input)?;
    let source = match header.src() {
        Some(x) => x.0,
        None => return Ok(None), // todo: is this possible? why?
    };

    let (mut input, (_timestamp, _beacon_interval, _capability_info)) =
        tuple((le_u64, le_u16, le_u16))(input)?;

    let mut elements = Vec::new();
    loop {
        let element_id;
        let length;
        let data;
        (input, (element_id, length)) = tuple((u8, u8))(input)?;
        (input, data) = take(length)(input)?;

        // if use_ie(element_id) {
        //     let data = match element_id {
        //         221 => &data[0..3],
        //         _ => data,
        //     };
        elements.push((element_id, data.to_vec()));
        // } else {
        //     elements.push((element_id, Vec::new()))
        // };

        if input.len() <= 4 {
            break;
        }
    }

    Ok(Some(Beacon { source, elements }))
}

pub fn use_ie(id: u8) -> bool {
    match id {
        0 => true,   // ssid
        1 => true,   // supported rates
        7 => true,   // country
        48 => true,  // security information
        50 => true,  // extended support rates
        127 => true, // extended capabilities

        3 => false,   // ds params - includes channel number
        5 => false,   // traffic indication map - changes over time
        11 => false,  // qbss load - channel load over time
        42 => false,  // extended rate phy info - dunno what it means but it changes
        45 => false,  // ht capabilties - dont really know why this changes
        61 => false,  // ht operation - includes channel number
        67 => false,  // bss available capacity - channel load over time
        201 => false, // reduced neighbour report - 6ghz neighbour scans, helps clients discover aps in 6ghz
        221 => true,  // vendor specific, todo: could include oui?
        255 => false, // extended - todo

        // these seem to change rarely?
        70 => false,
        74 => false,

        // to look into:
        // 45 => (), // ht capabilities
        // 70 => (), // radio measurement capabilities
        // 133 => (), // cisco
        _ => false,
    }
}
