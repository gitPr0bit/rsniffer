pub mod parser {
    use pnet::packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Packet, self},
        udp::UdpPacket,
        tcp::TcpPacket,
        Packet, arp::ArpPacket, PacketSize, ipv6::Ipv6Packet, icmp::IcmpPacket, icmpv6::Icmpv6Packet,
    };
    
    use crate::lib::report::report::TrafficDetail;


    pub fn parse(packet: &pcap::Packet) -> TrafficDetail {
        let mut result = TrafficDetail::new();

        parse_layer2(packet, &mut result);

        return result;
    }

    fn parse_layer2(packet: &pcap::Packet, res: &mut TrafficDetail) {
        let ethernet = EthernetPacket::new(packet.data).unwrap();

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
                res.src_ip = ipv4_packet.get_source().to_string();
                res.dst_ip = ipv4_packet.get_destination().to_string();

                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp  => parse_udp(IpPacket::V4(&ipv4_packet), res),
                    IpNextHeaderProtocols::Tcp  => parse_tcp(IpPacket::V4(&ipv4_packet), res),
                    _ => res.handled = false
                }
            },
            EtherTypes::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new(ethernet.payload()).unwrap();
                res.src_ip = ipv6_packet.get_source().to_string();
                res.dst_ip = ipv6_packet.get_destination().to_string();

                match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Udp => parse_udp(IpPacket::V6(&ipv6_packet), res),
                    IpNextHeaderProtocols::Tcp => parse_tcp(IpPacket::V6(&ipv6_packet), res),
                    _ => res.handled = false
                }
            },
            _ => res.handled = false
        }
    }

    fn parse_udp(packet: IpPacket, res: &mut TrafficDetail) {
        let udp_packet = match packet {
            IpPacket::V4(ipv4_packet) => UdpPacket::new(ipv4_packet.payload()).unwrap(),
            IpPacket::V6(ipv6_packet) => UdpPacket::new(ipv6_packet.payload()).unwrap()
        };

        res.src_port = udp_packet.get_source().to_string();
        res.dst_port = udp_packet.get_destination().to_string();
        res.bytes = usize::from(udp_packet.payload().len());
    }

    fn parse_tcp(packet: IpPacket, res: &mut TrafficDetail) {
        let tcp_packet = match packet {
            IpPacket::V4(ipv4_packet) => TcpPacket::new(ipv4_packet.payload()).unwrap(),
            IpPacket::V6(ipv6_packet) => TcpPacket::new(ipv6_packet.payload()).unwrap()
        };

        res.src_port = tcp_packet.get_source().to_string();
        res.dst_port = tcp_packet.get_destination().to_string();
        res.bytes = usize::from(tcp_packet.payload().len());
    }



    /*************************** Utilities ***************************/
    enum IpPacket<'a> {
        V4(&'a Ipv4Packet<'a>),
        V6(&'a Ipv6Packet<'a>)
    }
}