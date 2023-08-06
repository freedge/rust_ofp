use std::os::unix::net::UnixStream;
use crate::rust_ofp::ofp_controller::openflow0x01::OF0x01Controller;
use crate::rust_ofp::openflow0x01::{NxtPacketIn2, SwitchFeatures,SwitchConfig,ControllerId,PacketInFormat};
use crate::rust_ofp::openflow0x01::message::Message;
use crate::rust_ofp::ofp_controller::OfpController;
use std::fmt;
use crate::rust_ofp::packet::{Packet,Nw,Tp};
extern crate tls_parser;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::error::Error;
use std::io::BufRead;

#[derive(Debug)]
pub struct NotATLSPayload;
#[derive(Debug)]
pub struct NoSNIFound;

#[derive(Debug)]
pub struct NotATLSHandshake;

impl fmt::Display for NotATLSPayload {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "Not a TLS payload")
    }
}
impl fmt::Display for NoSNIFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "No SNI Found")
    }
}
impl fmt::Display for NotATLSHandshake {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Not a TLS handshake")
    }
}

impl std::error::Error for  NoSNIFound {}
impl std::error::Error for  NotATLSPayload {}
impl std::error::Error for  NotATLSHandshake {}

/* we expect a TCP message and panic if that's not the case.
    * Returns the SNI of the TLS payload or an error
    */
pub fn parse_sni(packet: &Vec<u8>) -> Result<String, Box<dyn Error>> {
    let packet = Packet::parse(packet);
    let Nw::Ip(ip) = packet.nw else {panic!("not IP")};
    let Tp::Tcp(tcp) = ip.tp else {panic!("not TCP")};
    let mut bytes = Cursor::new(tcp.payload);
    /* the parser parses the TCP header until the option part and returns options + payload
        * as payload. We skip the option part to get the payload */
    bytes.consume(4 * (tcp.offset as usize) - 20);

    /* TCP payload. This is what we are supposed to receive, so
        * we should not panic if something is incorrect. */
    /* SSL Handshake */
    let tls_content_type = bytes.read_u8()?;
    let tls_version = bytes.read_u16::<BigEndian>()?;
    bytes.consume(2);

    println!("Parsing ttl={} :{}->:{} {tls_content_type:#02x} {tls_version:#02x} [{:?}]", ip.ttl, tcp.src, tcp.dst, tcp.flags);

    let remaining = &bytes.get_ref()[(bytes.position() as usize)..];
    // tls_parser::parse_tls_message_handshake(bytes.remaining_slice());

    if tls_content_type != 0x16 {
        return Err(NotATLSPayload.into())
    }
    match tls_parser::parse_tls_message_handshake(remaining) {
        Ok((_res, msg)) => {
            if let tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ClientHello(h)) = msg  {
                if let Some(ext) = h.ext {
                    if let Ok((_res, exts)) = tls_parser::parse_tls_client_hello_extensions(ext) {
                        for e in exts.iter() {
                            if let tls_parser::TlsExtension::SNI(sni) = e {
                                let (_, s) = sni[0];
                                let snistr = std::str::from_utf8(s)?;
                                println!("parsed SNI={snistr}");
                                return Ok(snistr.to_string());
                            }
                        }
                    }
                }
            }
        }
        Err(_) => {
            return Err(NotATLSHandshake.into());
        }
    }
    Err(NoSNIFound.into())
}

pub fn force_reg8_bit(ret: u64, metadata: &mut Vec<u8>, skip: bool) {
    /* ret is like that: 8001080800000032 */
    /*                   8001              vendor */
    /*                       04            field =4 no mask */
    /*                         08          length */
    /*                                00110010b */
    /* should match reg8[18] */
    assert_eq!(ret & 0xFFFFFFFFFFFFFFE0, 0x8001080800000020);
    let target_vendor = ((ret & 0xFFFF000000000000) >> 48) as u32;
    let target_field =  ((ret & 0x0000FE0000000000) >> 41) as u32;
    let target_bit = ret & 0x1f;

    /* need to parse those metadata as well probably */
    let mut size = metadata.len();
    let mut bytes = Cursor::new(metadata);
    while size > 0 {
        let nx_header = bytes.read_u32::<BigEndian>().unwrap();
        let vendor = (nx_header >> 16) & 0xffff;
        assert!(vendor != 0xffff, "experimental feature not supported");
        let hasmask = (nx_header & 0x0100) == 0x0100;
        let field = (nx_header & 0xFE00) >> 9;
        let len = (nx_header & 0xFF) as usize;
        // println!("header {:x} {len} mask={hasmask} vendor={vendor:x} field={field}", nx_header);
        if vendor == target_vendor && field == target_field  && hasmask && len == 16 {
            // parsing { .nf = { NXM_HEADER(0x0,0x8001,4,0,8), 4, "OXM_OF_PKT_REG4", MFF_XREG4 } },
            let mut reg8 = bytes.read_u32::<BigEndian>().unwrap();
            if !skip {
                reg8 |= 0x1 << target_bit;
            }
            // rewrite reg8
            bytes.set_position(bytes.position()-4);
            bytes.write_u32::<BigEndian>(reg8).unwrap();
            let reg9 = bytes.read_u32::<BigEndian>().unwrap();
            let mask8 = bytes.read_u32::<BigEndian>().unwrap();
            let mask9 = bytes.read_u32::<BigEndian>().unwrap();
            println!("reg8={reg8:x}/{mask8:x} reg9={reg9:x}/{mask9:x}");
        } else {
            bytes.consume(len);
        }
        size -= 4;
        size -= len;
    }
}

fn handle_acl_sni(mut packet: NxtPacketIn2) -> NxtPacketIn2 {
    let snistr = parse_sni(&packet.packet).unwrap_or("".to_string());

    let mut bytes = Cursor::new(packet.userdata.unwrap());
    let opcode = bytes.read_u32::<BigEndian>().unwrap();
    assert!(opcode == 0x1b, "not an inspect action");

    let fill = bytes.read_u32::<BigEndian>().unwrap();
    let ret = bytes.read_u64::<BigEndian>().unwrap();

    let globstr = std::str::from_utf8(&bytes.get_ref()[16..]).unwrap();
    println!("glob = {globstr}, opcode = {opcode:x}, fill = {fill:x}, ret = {ret:x}");

    let accept = snistr.contains(globstr);
    force_reg8_bit(ret, &mut packet.metadata, accept);

    NxtPacketIn2 { packet: packet.packet,
        cookie: packet.cookie, table_id: packet.table_id, reason: packet.reason,
        continuation: packet.continuation, userdata: None,
        metadata: packet.metadata }
}

pub struct InspectController {
}

impl InspectController {
}

impl OF0x01Controller for InspectController {
    fn new() -> InspectController {
        InspectController {  }
    }

    fn switch_connected(&mut self, _: u64, _: SwitchFeatures, xid: u32, stream: &mut UnixStream) {
        let switch_config = SwitchConfig {
            flags: 0,
            miss_send_len: 1234,
        };
        let controller_id = ControllerId {
            controller_id: 42,
        };
        let packet_in_format = PacketInFormat::PacketInNxt2;
        Self::send_message(xid, Message::SetConfig(switch_config), stream);
        Self::send_message(xid, Message::SetControllerId(controller_id), stream);
        Self::send_message(xid, Message::SetPacketInFormat(packet_in_format), stream);
    }

    fn switch_disconnected(&mut self, _: u64) {}

    fn packet_in2(&mut self, _sw: u64, xid: u32, pkt: NxtPacketIn2, stream: &mut UnixStream) {
        // we received our glorious packet
        let pkt2 = handle_acl_sni(pkt);
        Self::send_message(xid, Message::NxtResume(pkt2), stream)
    }
}
