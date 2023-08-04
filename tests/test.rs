extern crate rust_ofp;


#[cfg(test)]
pub mod test {
    use rust_ofp::ofp_controller::openflow0x01::{parse_sni,NoSNIFound,NotATLSPayload,NotATLSHandshake};

    fn read_hexstream(hexstream: &str) -> Vec<u8> {
        let mut packet : Vec<u8> = vec![];
        let mut it = hexstream.chars();
        let mut n = it.next();
        while let Some(high) = n {
            let low = it.next().unwrap();
            let s = String::new() + &high.to_string() + &low.to_string();
            let c = i64::from_str_radix(&s, 16).unwrap() as u8;
            packet.push(c);
            n = it.next();
        };
        packet
    }

    #[test]
    fn parse_a_tls_packet() {
        let hexstream = "00000000000150540000030008004500023930c840004006e7ff0ae12a0ac0a82a64964a1f90591f3b9d2b78ebe8801801f6222300000101080ad21a263418f4d74b1603010200010001fc0303f4563f59b6523a9f49ae262f7aed004da4de46674a978ebfed9a88576d834060201bd63a6b189abc60b954d7830c291720e25b5e1967566dc1d631a759d7c808bd000a130213031301130400ff010001a900000014001200000f7777772e6578616d706c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d00208956dbe3e401c96f9b1c096fd4e4e99b4bdd0e78cd4b0f741d69f6fc2f383472001500f400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let packet = read_hexstream(hexstream);
        let result = parse_sni(&packet);


        assert_eq!(result.unwrap(), "www.example.com".to_string());

    }

    #[test]
    fn parse_a_tls_packet_no_sni() {
        let hexstream = "000000000001505400000300080045000239ba3b400040065e8c0ae12a0ac0a82a64b1641f90ede3efaa05478d4d801801f6222300000101080ad23820711912d0bd1603010200010001fc030363bceac350cd4447d742fcf14e9a8733b7201085f0b512bf4d5789b36e0d2053208ecefe0d032484b0e05a4d1f54a4cfad44e8ebae3664ac90185ca9db7a50fdf800481302130313011304c02cc030cca9cca8c0adc02bc02fc0acc023c027c00ac014c009c013009dc09d009cc09c003d003c0035002f009fccaac09f009ec09e006b00670039003300ff0100016b000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d00220020040305030603080708080809080a080b08040805080604010501060103030301002b00050403040303002d00020101003300260024001d00200d0ad2b510087edd6893c4497a14f04503420aeda1f7417a7959ad3939751c4c001500c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let packet = read_hexstream(hexstream);
        let result = parse_sni(&packet);

        let e = result.err().unwrap();
        assert!(e.is::<NoSNIFound>());
    }

    #[test]
    fn parse_a_http_packet_no_sni() {
        let hexstream = "00000000000150540000030008004500008693864000400686f40ae12a0ac0a82a64c6441f90656e8470d76a52cb801801f6207000000101080ad2383ea71912efbf474554202f20485454502f312e310d0a486f73743a203139322e3136382e34322e3130303a383038300d0a557365722d4167656e743a206375726c2f382e322e300d0a4163636570743a202a2f2a0d0a0d0a";
        let packet = read_hexstream(hexstream);
        let result = parse_sni(&packet);

        let e = result.err().unwrap();
        assert!(e.is::<NotATLSPayload>());
    }

    #[test]
    fn parse_a_tcp_syn_packet() {
        let hexstream = "00000000000150540000030008004500003cba3840004006608c0ae12a0ac0a82a64b1641f90ede3efa900000000a002faf020260000020405b40402080ad2381fa40000000001030307";
        let packet = read_hexstream(hexstream);
        let result = parse_sni(&packet);

        let e = result.err().unwrap();
        assert!(e.is::<std::io::Error>());
    }

    #[test]
    fn parse_broken_tls_packet() {
        let hexstream = "a02942156e9068a37819e2ea08004500009782da0000370608655db8d822c0a8019f01bb9ace15f818a3bbf1b1b180180083d4de00000101080ae51cf377d9346dc31603030058020000540303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c20898cef85e0453da6e0db7136d97a12b87b0ea347a29b4fb23daa2137807a3122130200000c002b00020304003300020017140303000101";

        let packet = read_hexstream(&hexstream[..hexstream.len()-20]);
        let result = parse_sni(&packet);

        let e = result.err().unwrap();
        assert!(e.is::<NotATLSHandshake>());
    }
}
