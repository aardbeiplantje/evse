package ip_packet;

use strict;
use warnings;

use utils::logger;

use Socket qw(AF_INET AF_INET6 inet_ntoa inet_ntop);

sub decode {
    my ($ip_pkt) = @_;
    my $pkt = {};
    logger::debug(" - ip_pkt[hex]: ".to_hex($$ip_pkt)."");
    logger::debug(" - ip_pkt_size: ".length($$ip_pkt));
    my $ip_version = unpack("C", $$ip_pkt);
    my ($iphdr, $iplen, $ipproto);
    my ($sip, $dip, $sport, $dport);
    if(($ip_version & 0xf0) == 0x40){
        my $ip_ihl = $ip_version & 0x0f;
        my $ip_hdr_size = $ip_ihl * 4;
        $iphdr = unpack("a".($ip_ihl*4), substr($$ip_pkt, 0, $ip_hdr_size, ''));
        logger::debug(" - iphdr[hex]: ".to_hex($iphdr)."");
        # let's parse the ipv4 header
        my ($ip_version_ihl, $ip_dscp_ecn, $ip_tot_len, $ip_id, $ip_flags_fragment_offset, $ip_ttl, $ip_protocol, $ip_check, $ip_saddr, $ip_daddr) = unpack("CCS>S>S>CCa2a4a4", $iphdr);
        my $ip_fragment_offset = $ip_flags_fragment_offset & 0x1fff;
        my $ip_flags = $ip_flags_fragment_offset >> 13;
        my $ip_flag_df = $ip_flags & 0x02;
        my $ip_flag_mf = $ip_flags & 0x01;
        logger::debug(" - ip_version: $ip_version");
        logger::debug(" - ip_ihl: $ip_ihl");
        logger::debug(" - ip_dscp_ecn: $ip_dscp_ecn");
        logger::debug(" - ip_tot_len: $ip_tot_len");
        logger::debug(" - ip_id: $ip_id");
        logger::debug(" - ip_flags: $ip_flags");
        logger::debug(" - ip_fragment_offset: $ip_fragment_offset");
        logger::debug(" - ip_flag_df: $ip_flag_df");
        logger::debug(" - ip_flag_mf: $ip_flag_mf");
        logger::debug(" - ip_ttl: $ip_ttl");
        logger::debug(" - ip_protocol: $ip_protocol");
        logger::debug(" - ip_check: ".to_hex($ip_check));
        logger::debug(" - ip_saddr: ".($sip = inet_ntoa($ip_saddr)));
        logger::debug(" - ip_daddr: ".($dip = inet_ntoa($ip_daddr)));
        my $ip_options = substr($iphdr, 20, $ip_ihl*4, '')
            if $ip_ihl > 5;
        $ipproto = $ip_protocol;
        $iplen   = $ip_tot_len;
    } elsif(($ip_version & 0xf0) == 0x60){
        $iphdr = unpack("a40", substr($$ip_pkt, 0, 40, ''));
        logger::debug(" - ipv6hdr[hex]: ".to_hex($iphdr)."");
        # let's parse the ipv6 header
        my ($ip6_version_tc, $ip6_tc_fl, $ip6_flow_label, $ip6_payload_len, $ip6_next_header, $ip6_hop_limit, $ip6_src, $ip6_dst) = unpack("CCS>S>CCa16a16", $iphdr);
        my $ip6_version = $ip6_version_tc & 0xff;
        my $ip6_tc = $ip6_tc_fl & 0xf0;
        $ip6_tc = ($ip6_tc >> 4)|(($ip6_version_tc & 0x0f) << 4);
        $ip6_flow_label |= ($ip6_tc_fl & 0x0f) << 16;

        logger::debug(" - ip6_version: $ip6_version");
        logger::debug(" - ip6_traffic_class: $ip6_tc");
        logger::debug(" - ip6_flow_label: $ip6_flow_label");
        logger::debug(" - ip6_payload_len: $ip6_payload_len");
        logger::debug(" - ip6_next_header: $ip6_next_header");
        logger::debug(" - ip6_hop_limit: $ip6_hop_limit");
        logger::debug(" - ip6_src: ".($sip = inet_ntop(AF_INET6, $ip6_src)));
        logger::debug(" - ip6_dst: ".($dip = inet_ntop(AF_INET6, $ip6_dst)));
        $ipproto = $ip6_next_header;
        $iplen   = $ip6_payload_len;
    } else {
        logger::debug(" - unknown ip_version: $ip_version:".($ip_version & 0xff)."");
        return;
    }
    if($ipproto == 6){ # TCP
        my $tcphdr = substr($$ip_pkt, 0, 20, '');
        # now we parse the tcp header
        logger::debug(" - tcphdr[hex]: ".to_hex($tcphdr)."");
        my ($tcp_sport, $tcp_dport, $tcp_seq, $tcp_ack_seq, $tcp_data_off_res, $tcp_flags, $tcp_window, $tcp_checksum, $tcp_urg_ptr) = unpack("S>S>L>L>CCS>a2S>", $tcphdr);
        ($sport, $dport) = ($tcp_sport, $tcp_dport);
        my $tcp_data_off = $tcp_data_off_res >> 4;
        my $tcp_reserved = $tcp_data_off_res & 0x0f;
	logger::debug(" - tcphdr[chksum]: ".to_hex($tcp_checksum));
        logger::debug(" - tcp_sport: $tcp_sport");
        logger::debug(" - tcp_dport: $tcp_dport");
        logger::debug(" - tcp_seq: $tcp_seq");
        logger::debug(" - tcp_ack_seq: $tcp_ack_seq");
        logger::debug(" - tcp_data_off: $tcp_data_off");
        logger::debug(" - tcp_res: $tcp_reserved");
        logger::debug(" - tcp_flags: $tcp_flags");
        # and parse the flags
        my $tcp_fin = ($tcp_flags & 0x01);
        my $tcp_syn = ($tcp_flags & 0x02) >> 1;
        my $tcp_rst = ($tcp_flags & 0x04) >> 2;
        my $tcp_psh = ($tcp_flags & 0x08) >> 3;
        my $tcp_ack = ($tcp_flags & 0x10) >> 4;
        my $tcp_urg = ($tcp_flags & 0x20) >> 5;
        my $tcp_ece = ($tcp_flags & 0x40) >> 6;
        my $tcp_cwr = ($tcp_flags & 0x80) >> 7;
        logger::debug(" - tcp_fin: $tcp_fin");
        logger::debug(" - tcp_syn: $tcp_syn");
        logger::debug(" - tcp_rst: $tcp_rst");
        logger::debug(" - tcp_psh: $tcp_psh");
        logger::debug(" - tcp_ack: $tcp_ack");
        logger::debug(" - tcp_urg: $tcp_urg");
        logger::debug(" - tcp_ece: $tcp_ece");
        logger::debug(" - tcp_cwr: $tcp_cwr");
        logger::debug(" - tcp_window: $tcp_window");
        logger::debug(" - tcp_checksum: ".to_hex($tcp_checksum));
        logger::debug(" - tcp_urg_ptr: $tcp_urg_ptr");
        my $p_size;
        if($tcp_data_off > 5){
            my $tcp_options = substr($$ip_pkt, 0, $tcp_data_off*4-20, '');
            logger::debug(" - tcp_options[hex]: ".to_hex($tcp_options));
            $p_size = $iplen - $tcp_data_off*4;
        } else {
            # verify this somehow?
            $p_size = $iplen - 20;
        }
        logger::debug(" - payload_size: $p_size");
        if($p_size > 0){
            my $payload = substr($$ip_pkt, 0, $p_size, '');
            logger::debug(" - payload_size: $p_size");
            logger::debug(" - payload[hex]: ".to_hex($payload));
            logger::debug(" - payload[raw]: ".$payload);
            $pkt->{data} = $payload;
        }
        $pkt->{tcp_flags} = $tcp_flags;
        $pkt->{seq_num} = $tcp_seq;
        $pkt->{is_tcp} = 1;
    } elsif($ipproto == 1) { # ICMP
        my $icmphdr = substr($$ip_pkt, 0, 8, '');
        # now we parse the icmp header
        logger::debug(" - icmphdr[hex]: ".to_hex($icmphdr)."");
        my ($icmp_type, $icmp_code, $icmp_check, $icmp_payload) = unpack("CCS>a4", $icmphdr);
        logger::debug(" - icmp_type: $icmp_type");
        logger::debug(" - icmp_code: $icmp_code");
        logger::debug(" - icmp_check: ".to_hex($icmp_check));
        logger::debug(" - icmp_payload[hex]: ".to_hex($icmp_payload));
    } elsif($ipproto == 0){ # IPv6 HOPOPT
    } elsif($ipproto == 2){ # IGMP
    } elsif($ipproto == 17){ # UDP
        my $udphdr = substr($$ip_pkt, 0, 8, '');
        # now we parse the tcp header
        logger::debug(" - udphdr[hex]: ".to_hex($udphdr)."");
        my ($udp_sport, $udp_dport, $pkt_len, $pkt_chksum) = unpack("S>S>S>S>", $udphdr);
	logger::debug(" - udphrd[chksum]: ".to_hex($pkt_chksum));
        ($sport, $dport) = ($udp_sport, $udp_dport);
        if($pkt_len > 0){
            my $payload = substr($$ip_pkt, 0, $pkt_len, '');
            logger::debug(" - payload_size: $pkt_len");
            logger::debug(" - payload[hex]: ".to_hex($payload));
            logger::debug(" - payload[raw]: ".$payload);
            $pkt->{data} = $payload;
        }
    } elsif($ipproto == 41){ # IPv6 ENCAP
    } elsif($ipproto == 43){ # IPv6 Route
    } elsif($ipproto == 44){ # IPv6 Frag
    } elsif($ipproto == 50){ # ESP
    } elsif($ipproto == 51){ # AH
    } elsif($ipproto == 58){ # ICMPv6
    } elsif($ipproto == 59){ # No Next Header
    } elsif($ipproto == 60){ # Destination Options
    } elsif($ipproto == 103){ # PIM
    } elsif($ipproto == 132){ # SCTP
    } elsif($ipproto == 133){ # FC
    } elsif($ipproto == 135){ # Mobility Header
    } elsif($ipproto == 139){ # HIP
    } elsif($ipproto == 140){ # Shim6
    } elsif($ipproto == 141){ # WESP
    } elsif($ipproto == 142){ # ROHC
    } else {
        logger::debug(" - unknown ipproto: $ipproto");
    }
    $pkt->{conn} = ["$sip:".($sport//0), "$dip:".($dport//0)]
        if $sip // $dip // $sport // $dport // 0;
    return $pkt;
}

sub to_hex {
    my $b = \$_[0];
    return join("",map {sprintf("%02x", ord $_)} split '', $$b//"");
}

1;
