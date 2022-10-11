use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, self},
    udp::UdpPacket,
    tcp::TcpPacket,
    Packet, arp::ArpPacket, PacketSize,
};

use report::TrafficDetail;

pub mod parser {

    pub fn parse(packet: &pcap::Packet) -> TrafficDetail {
        let mut result = TrafficDetail::new();

        parse_layer2(packet, &mut result);
    }

    fn parse_layer2(packet: &pcap::Packet, res: &mut TrafficDetail) {
        let ethernet = EthernetPacket::new(packet.data).unwrap();

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
                res.src_ip = ipv4_packet.get_source().to_string();
                res.dst_ip = ipv4_packet.get_destination().to_string();

                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => parse_udp(packet, res),
                    IpNextHeaderProtocols::Tcp => parse_tcp(packet, res)
                }
            },
            EtherTypes::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new(ethernet.payload()).unwrap();
                res.src_ip = ipv6_packet.get_source().to_string();
                res.dst_ip = ipv6_packet.get_destination().to_string();

                match ipv6_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => parse_udp(packet, res),
                    IpNextHeaderProtocols::Tcp => parse_tcp(packet, res)
                }
            },
            _ => println!("unhandled packet: {:?}", ethernet)
        }
    }

    fn parse_udp(packet: &pcap::Packet, res: &mut TrafficDetail) {
    }

    fn parse_tcp(packet: &pcap::Packet, res: &mut TrafficDetail) {
    }

}