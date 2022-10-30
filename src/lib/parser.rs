pub mod parser {
    use chrono::{DateTime, Utc, NaiveDateTime};
    use crossterm::style::Stylize;
    use pcap::Device;
    use pnet::packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Packet},
        udp::UdpPacket,
        tcp::TcpPacket,
        Packet, ipv6::Ipv6Packet
    };
    
    use crate::lib::report::report::TrafficDetail;


    pub fn parse(packet: &pcap::Packet) -> TrafficDetail {
        let mut result = TrafficDetail::new();

        parse_timestamp(packet, &mut result);
        parse_layer2(packet, &mut result);

        return result;
    }

    fn parse_timestamp(packet: &pcap::Packet, res: &mut TrafficDetail) {
        // Get timestamp from header
        let ts = packet.header.ts.tv_sec;
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(ts.into(), 0), Utc);

        res.first_ts = dt.to_string();
        res.last_ts = dt.to_string();
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
            IpPacket::V4(ipv4_packet) => UdpPacket::new(ipv4_packet.payload()).or(None),
            IpPacket::V6(ipv6_packet) => UdpPacket::new(ipv6_packet.payload()).or(None)
        };

        match udp_packet {
            Some(packet) => {
                res.src_port = packet.get_source().to_string();
                res.dst_port = packet.get_destination().to_string();
                res.bytes = usize::from(packet.payload().len());
                res.protocol = String::from("UDP");
            },
            None => res.handled = false
        }
        
    }

    fn parse_tcp(packet: IpPacket, res: &mut TrafficDetail) {
        let tcp_packet: Option<TcpPacket> = match packet {
            IpPacket::V4(ipv4_packet) => TcpPacket::new(ipv4_packet.payload()).or(None),
            IpPacket::V6(ipv6_packet) => TcpPacket::new(ipv6_packet.payload()).or(None)
        };

        match tcp_packet {
            Some(packet) => {
                res.src_port = packet.get_source().to_string();
                res.dst_port = packet.get_destination().to_string();
                res.bytes = usize::from(packet.payload().len());
                res.protocol = String::from("TCP");
            },
            None => res.handled = false
        }
    }

    pub fn parse_device(dev: &Device, index: Option<usize>) -> String {
        let mut res = String::new();
        let i = match index { 
            Some(indx) => format!("{}. ", indx), 
            None => String::new()            
        };

        // name
        res.push_str(&format!("{}{:<20}", i, &dev.name));

        // description
        match &dev.desc {
            Some(desc) => { res.push_str(&format!("\t{}", &desc)); },
            None => { res.push_str(&format!("\t{}", "No description")); }
        }

        // addresses
        for a in &dev.addresses {
            res.push_str(&format!("\n\r{:<20}\taddress: ", ""));
            res.push_str(&a.addr.to_string());
            
            res.push_str(&format!("\n\r{:<20}\tnetmask: ", ""));
            match a.netmask {
                Some(netmask) => { res.push_str(&netmask.to_string()); },
                None => {}
            }

            match a.broadcast_addr {
                Some(baddr) => {
                    res.push_str(&format!("\n\r{:<20}\tbroadcast address: ", ""));
                    res.push_str(&baddr.to_string()); 
                },
                None => {}
            }
        }

        return res;
    }



    /*************************** Utilities ***************************/
    enum IpPacket<'a> {
        V4(&'a Ipv4Packet<'a>),
        V6(&'a Ipv6Packet<'a>)
    }
}