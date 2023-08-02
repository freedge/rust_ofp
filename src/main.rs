use std::os::unix::net::UnixStream;

extern crate rust_ofp;
use rust_ofp::learning_switch::LearningSwitch;
use rust_ofp::ofp_controller::OfpController;

fn main() {
    let socket_path = "/var/run/openvswitch/br-int.mgmt";

    let stream =
        UnixStream::connect(socket_path);


    match stream {
        Ok(mut stream) => {
            println!("{:?}", stream);
            LearningSwitch::handle_client_connected(&mut stream);
        }
        Err(_) => {
            // connection failed
            panic!("Connection failed")
        }
    }
}
