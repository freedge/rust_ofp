
use std::os::unix::net::UnixStream;
use crate::rust_ofp::ofp_message::OfpMessage;



/// OpenFlow Controller
///
/// Version-agnostic API for implementing an OpenFlow controller.
pub trait OfpController {
    /// OpenFlow message type supporting the same protocol version as the controller.
    type Message: OfpMessage;

    /// Send a message to the node associated with the given `UnixStream`.
    fn send_message(_: u32, _: Self::Message, _: &mut UnixStream);
    /// Perform handshake and begin loop reading incoming messages from client stream.
    fn handle_client_connected(_: &mut UnixStream);
}

pub mod openflow0x01 {
    use super::*;
    use std::io::{Write, Read};
    use std::marker::PhantomData;
    use std::os::unix::net::UnixStream;

    use crate::rust_ofp::ofp_header::OfpHeader;
    use crate::rust_ofp::ofp_header::OfpVendorHeader;
    use crate::rust_ofp::ofp_message::OfpMessage;
    use crate::rust_ofp::openflow0x01::{FlowMod, PacketIn, NxtPacketIn2, PacketOut, SwitchFeatures};
    use crate::rust_ofp::openflow0x01::message::Message;

    #[derive(Debug)]
    struct ThreadState<Cntl> {
        switch_id: Option<u64>,
        phantom: PhantomData<Cntl>,
    }

    impl<Cntl: OF0x01Controller> ThreadState<Cntl> {

        fn process_message(&mut self,
                           cntl: &mut Cntl,
                           xid: u32,
                           msg: Message,
                           stream: &mut UnixStream) {
            match msg {
                Message::Hello => {
                    Cntl::send_message(xid, Message::FeaturesReq, stream);
                    println!("processing hello")
                }
                Message::Error(err) => println!("Error: {:?}", err),
                Message::EchoRequest(bytes) => {
                    Cntl::send_message(xid, Message::EchoReply(bytes), stream)
                }
                Message::EchoReply(_) => (),
                Message::FeaturesReq => (),
                Message::FeaturesReply(feats) => {
                    if self.switch_id.is_some() {
                        panic!("Switch connection already received.")
                    }
                    self.switch_id = Some(feats.datapath_id);
                    Cntl::switch_connected(cntl, feats.datapath_id, feats, xid, stream);
                    println!("all sent")
                }
                Message::FlowMod(_) => (),
                Message::PacketIn(_) => {
                    todo!();
                }
                Message::NxtPacketIn2(pkt) => {
                    Cntl::packet_in2(cntl, self.switch_id.unwrap(), xid, pkt, stream)
                }
                Message::NxtResume(_) |
                Message::FlowRemoved(_) |
                Message::PortStatus(_) |
                Message::PacketOut(_) |
                Message::BarrierRequest |
                Message::SetConfig(_) |
                Message::SetControllerId(_) |
                Message::SetPacketInFormat(_) |
                Message::BarrierReply => (),
            }
        }

    }

    /// OpenFlow0x01 Controller API
    ///
    /// OpenFlow 1.0-specific API for communicating between a controller and the dataplane.
    pub trait OF0x01Controller: OfpController<Message = Message> {
        /// Create a new Controller.
        fn new() -> Self;
        /// Callback invoked with `sw` when a switch with identifier `sw` connects to
        /// the controller.
        fn switch_connected(&mut self, sw: u64, feats: SwitchFeatures, xid: u32, stream: &mut UnixStream);
        /// Callback invoked with `sw` when a switch with identifier `sw` disconnects
        /// from the controller.
        fn switch_disconnected(&mut self, sw: u64);
        /// Callback invoked when a packet `pkt` with transaction ID `xid` from
        /// switch `sw` arrives at the controller.
        fn packet_in(&mut self, _sw: u64, _xid: u32, _pkt: PacketIn, _stream: &mut UnixStream) {
            todo!();
        }
        fn packet_in2(&mut self, sw: u64, xid: u32, pkt: NxtPacketIn2, stream: &mut UnixStream);

        /// Send packet `pkt` with transaction ID `xid` to switch `sw` from the controller.
        fn send_packet_out(_: u64, xid: u32, pkt: PacketOut, stream: &mut UnixStream) {
            Self::send_message(xid, Message::PacketOut(pkt), stream)
        }

        /// Send flowmod `flow` with transaction ID `xid` to switch `sw` from the controller.
        fn send_flow_mod(_: u64, xid: u32, flow: FlowMod, stream: &mut UnixStream) {
            Self::send_message(xid, Message::FlowMod(flow), stream)
        }

        /// Send barrier request with transaction ID `xid` to switch `sw` from the controller.
        /// Guarantees switch `sw` processes messages prior to barrier before messages after.
        fn send_barrier_request(_: u64, xid: u32, stream: &mut UnixStream) {
            Self::send_message(xid, Message::BarrierRequest, stream)
        }
    }

    impl<Controller: OF0x01Controller> OfpController for Controller {
        type Message = Message;

        fn send_message(xid: u32, message: Message, writer: &mut UnixStream) {
            let raw_msg = Message::marshal(xid, message);
            writer.write_all(&raw_msg).unwrap()
        }

        fn handle_client_connected(stream: &mut UnixStream) {
            let mut cntl = Controller::new();
            Controller::send_message(0, Message::Hello, stream);

            let mut buf = [0u8; 8];
            let mut thread_state = ThreadState::<Self> {
                switch_id: None,
                phantom: PhantomData,
            };

            loop {
                stream.read_exact(&mut buf).unwrap();
                let header = OfpHeader::parse(buf);
                let len = header.length();
                let (xid, body) = match header.type_code() {
                    crate::openflow0x01::MsgCode::Vendor => {
                        let mut buf = [0u8; 8];
                        stream.read_exact(&mut buf).unwrap();

                        let vendor_header = OfpVendorHeader::parse(header, buf);
                        let message_len: usize = len - OfpVendorHeader::size();
                        let mut message_buf = vec![0; message_len];
                        if message_len > 0 {
                            stream.read_exact(&mut message_buf).unwrap();
                        }
                        Message::parse_vendor(&vendor_header, &message_buf)
                    },
                    _ => {
                        let message_len = len - OfpHeader::size();
                        let mut message_buf = vec![0; message_len];
                        if message_len > 0 {
                            stream.read(&mut message_buf).unwrap();
                        }
                        Message::parse(&header, &message_buf)
                    }
                };
                thread_state.process_message(&mut cntl, xid, body, stream)
            }
        }
    }
}
