
use std::os::unix::net::UnixStream;

extern crate rust_ofp;
use rust_ofp::inspect_controller::InspectController;
use rust_ofp::ofp_controller::OfpController;

fn main() {
    let socket_path = "/var/run/openvswitch/br-int.mgmt";

    let mut stream = UnixStream::connect(socket_path).unwrap();

    InspectController::handle_client_connected(&mut stream);
}
