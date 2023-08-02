use std::os::unix::net::UnixStream;
use rust_ofp::ofp_message::OfpMessage;

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

    use rust_ofp::ofp_header::OfpHeader;
    use rust_ofp::ofp_message::OfpMessage;
    use rust_ofp::openflow0x01::{FlowMod, PacketIn, PacketOut, SwitchFeatures, SwitchConfig, ControllerId};
    use rust_ofp::openflow0x01::message::Message;

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
                    Cntl::switch_connected(cntl, feats.datapath_id, feats, stream);
                    let switch_config = SwitchConfig {
                        flags: 0,
                        miss_send_len: 1234,
                    };
                    let controller_id = ControllerId {
                        controller_id: 42,
                    };
                    Cntl::send_message(xid, Message::SetConfig(switch_config), stream);
                    Cntl::send_message(xid, Message::SetControllerId(controller_id), stream);
                    println!("all sent")
                }
                Message::FlowMod(_) => (),
                Message::PacketIn(pkt) => {
                    Cntl::packet_in(cntl, self.switch_id.unwrap(), xid, pkt, stream)
                }
                Message::FlowRemoved(_) |
                Message::PortStatus(_) |
                Message::PacketOut(_) |
                Message::BarrierRequest |
                Message::SetConfig(_) |
                Message::SetControllerId(_) |
                Message::BarrierReply => (),
            }
        }

        fn switch_disconnected(&self, cntl: &mut Cntl) {
            Cntl::switch_disconnected(cntl, self.switch_id.unwrap())
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
        fn switch_connected(&mut self, sw: u64, feats: SwitchFeatures, stream: &mut UnixStream);
        /// Callback invoked with `sw` when a switch with identifier `sw` disconnects
        /// from the controller.
        fn switch_disconnected(&mut self, sw: u64);
        /// Callback invoked when a packet `pkt` with transaction ID `xid` from
        /// switch `sw` arrives at the controller.
        fn packet_in(&mut self, sw: u64, xid: u32, pkt: PacketIn, stream: &mut UnixStream);

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
                let res = stream.read(&mut buf);
                match res {
                    Ok(num_bytes) if num_bytes > 0 => {
                        let header = OfpHeader::parse(buf);
                        let message_len = header.length() - OfpHeader::size();
                        let mut message_buf = vec![0; message_len];
                        if message_len > 0 {
                            let _ = stream.read(&mut message_buf);
                        }
                        let (xid, body) = Message::parse(&header, &message_buf);
                        thread_state.process_message(&mut cntl, xid, body, stream)
                    }
                    Ok(_) => {
                        println!("Connection closed reading header.");
                        break;
                    }
                    Err(e) => {
                        println!("{}", e);
                        thread_state.switch_disconnected(&mut cntl)
                    }
                }
            }
        }
    }
}
