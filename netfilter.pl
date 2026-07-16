#!/usr/bin/perl

use strict;
use warnings;

use FindBin;
use JSON::PP;

my $xor_key = $ENV{XOR_KEY};
my $where = $FindBin::Bin;

# Determine input mode: pcap/tcpdump or trace (L:<LEN>\n<DATA>)
my $input_file = $ARGV[0] // $ENV{NF_PKT_TRACE} // die "usage: $0 <file>";
my $nf_input   = $ENV{NF_INPUT} // 'pcap';  # 'pcap' (default) or 'trace'

use Socket qw(AF_INET SOCK_RAW);
use POSIX ();
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use File::Basename qw(dirname);
use File::Path qw(mkpath);
use FindBin;

use utils::netlink;
use utils::ip_packet;
use utils::pcap;

my $sf = {};
my $st = \($sf->{_nf_state} //= {});

if($nf_input eq 'trace') {
    # trace format: L:<LENGTH>\n<DATA> per packet
    open(my $rfh, '<', $input_file) or die $!;
    while(1){
        local $/ = "\n";
        my $h_msg = <$rfh>;
        last unless ($h_msg//"") =~ m/^L:(\d+)\n/;
        my $r = read($rfh, my $payload, $1)
            // die $!;
        last if $r == 0;
        handle_frame($sf, $st, \$payload);
    }
    close($rfh);

} else {
    # pcap/tcpdump format: stream-read, advance file pointer
    # PCAP global header is 24 bytes; detect byte order from magic number
    # then each record is 16-byte hdr + incl_len bytes of packet data
    open(my $pfh, '<:raw', $input_file) or die $!;

    # Read global header (24 bytes) once
    my $ghdr;
    read($pfh, $ghdr, 24) or die "pcap: short global header";

    # Detect byte order from pcap magic: 0xa1b2c3d4 = native, 0xd4c3b2a1 = swapped
    my $magic = unpack("V", $ghdr);  # little-endian probe
    my $be    = ($magic == 0xd4c3b2a1) ? 1 : 0;  # 1 => big-endian fields
    my $fmt   = $be ? "NNNN" : "LLLL";

    # Stream through pcap records
    while(1) {
        # Record header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
        my $rec_hdr;
        my $r = read($pfh, $rec_hdr, 16);
        last unless defined $r && $r == 16;
        my ($ts_sec, $ts_usec, $incl_len, $orig_len) = unpack($fmt, $rec_hdr);

        # incl_len includes Ethernet header (14 bytes);
        # read full frame data so pointer advances regardless of type
        my $ethhdr;
        my $frame_data;
        my $data_len = $incl_len;
        $r = read($pfh, $ethhdr, 14);
        last unless defined $r && $r == 14;
        my ($eth_dst, $eth_src, $eth_type) = unpack("a6a6S>", $ethhdr);

        # skip non-IPv4 packets by reading their data and moving on
        if ($eth_type != 0x0800) {
            $r = read($pfh, $frame_data, $data_len - 14);
            last unless defined $r && $r == ($data_len - 14);
            next;
        }

        my $ip_len = $incl_len - 14;
        my $ip_data;
        $r = read($pfh, $ip_data, $ip_len);
        last unless defined $r && $r == $ip_len;

        handle_frame($sf, $st, \$ip_data);
    }
    close($pfh);
}

sub handle_frame {
    my ($self, $st, $ip_pkt_ref) = @_;
    my $p_data = ip_packet::decode($ip_pkt_ref);
    logger::debug("payload", length($p_data->{data}//"")?to_hex($p_data->{data}):"");
    # process IP packet data
    handle_ip_data($st, $p_data, sub {
        my ($buffer_ref) = @_;
        # valid HTTP/WebSocket data
        if($xor_key){
            # XOR decode
            logger::debug("xor_key: $xor_key");
            my $decoded_msg = xor_msg($xor_key, $$buffer_ref);
            logger::debug("decoded_msg: $decoded_msg");

            # JSON Parse
            ocpp_msg_process($self, $decoded_msg);
        } else {
            logger::debug("ocpp msg: $$buffer_ref");
            ocpp_msg_process($self, $$buffer_ref);
        }
        return;
    });
}

sub log_data {
    my ($self, $msg) = @_;
    open(my $of, '>>', '&STDOUT');
    print {$of} $msg."\n";
    return;
}

sub ocpp_msg_process {
    my ($self, $msg) = @_;
    eval {
        # parse JSON + verify (simple)
        require JSON;
        my $ocpp_msg = JSON::decode_json($msg);
        die "not a valid OCPP message: $msg"
            unless ref($ocpp_msg) eq 'ARRAY' and scalar(@$ocpp_msg) >= 3;

        # if this is an ocpp 1.6j message, let's check whether it's a start
        # transaction, stop transaction or meter values message
        my $meter_value;
        if($ocpp_msg->[2] =~ m/^(MeterValues|StartTransaction|StopTransaction)$/ 
                and ref($ocpp_msg->[3]) eq 'HASH'){
            # get info from the message
            my $st = $ocpp_msg->[3];
            logger::debug("$ocpp_msg->[2] ", $st);
            my $id_tag = $st->{idTag} // '';
            my $connector_id = $st->{connectorId} // 0;

            # get the metervalue from a udp/uart rs485 modbus call to an
            # eastron SDM630, format:
            #   ...,eastron:sdm630:totalkwh*kWh,1968.61193847656
            #
            my $m_value = `LOGGER_STDERR=0 perl $FindBin::Bin/modbus.pl tcp://192.168.1.252:4196=1:Eastron::SDM630::TotalKWh`;
            if($?){
                logger::error("modbus.pl failed: $m_value");
                $m_value = '';
            }
            if(length($m_value)){
                chomp($m_value);
                logger::debug("modbus value: $m_value");
                if($m_value =~ s{.*totalkwh\*kWh,}{}){
                    if($m_value =~ m{^(\d+(\.\d+)?)$}){
                        $meter_value = $1;
                        logger::info("OCPP $ocpp_msg->[2] sdm630_meter_value=$meter_value");
                    } else {
                        logger::error("modbus value does not match expected format: $m_value");
                    }
                } else {
                    logger::error("modbus value does not match expected format: $m_value");
                }

            }
        } else {
            logger::debug("not a StartTransaction/StopTransaction/MeterValues message");
        }

        # make audit log
        if(defined $meter_value){
            print "$msg,$meter_value\n";
        } else {
            print "$msg\n";
        }

        # cool charging bool flag per idTag
        eval {
            my $idTag = $ocpp_msg->[3]{idTag};
            if      ($ocpp_msg->[2] eq "StartTransaction"){
            } elsif ($ocpp_msg->[2] eq "StopTransaction"){
            }
        };
        if($@){
            logger::error("problem logging blinkcharging metric: $@");
        }
    };
    if($@){
        logger::error("problem processing $msg: $@");
    }
    return;
}

sub handle_ip_data {
    my ($state, $pkt, $h_sub) = @_;
    logger::debug("handle payload?");
    return unless defined $pkt and defined $pkt->{conn};
    my $_st = $$state //= {};
    logger::debug("handle payload: yes");

    my $conn_k1 = join(",", @{$pkt->{conn}});
    my $conn_k2 = join(",", reverse @{$pkt->{conn}});

    # if we get a TCP_FIN, we should close the connection and cleanup
    if(defined $pkt->{tcp_flags}){
        if($pkt->{tcp_flags} & 0x01){
            logger::debug("TCP_FIN for ".join(",", @{$pkt->{conn}}));
            delete $_st->{$conn_k1};
            delete $_st->{$conn_k2};
            return;
        }
        if($pkt->{tcp_flags} & 0x02 and   $pkt->{tcp_flags} & 0x10){
            logger::debug("TCP_SYN ACK for ".join(",", @{$pkt->{conn}}));
        }
        if($pkt->{tcp_flags} & 0x02 and !($pkt->{tcp_flags} & 0x10)){
            logger::debug("TCP_SYN for ".join(",", @{$pkt->{conn}}));
        }
    }
    return unless defined $pkt and defined $pkt->{conn} and length($pkt->{data}//"");
    my $data_payload = $pkt->{data};
    my $st  =
            $_st->{$conn_k1} 
        //= $_st->{$conn_k2}
        //= {};
    $st->{buf} //= "";
    $st->{buf} .= $data_payload;
    my $buf = \$st->{buf};
    logger::debug("DATA:>>$$buf<<LENGTH:".length($$buf));

    # was this a HTTP request? client -> server
    my $req = $$buf =~ s{.*?(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s(.*?)\sHTTP/1\.\d\r\n(.*?)\r\n\r\n}{}ms;
    if($req){
        logger::debug("HTTP Request");
        logger::debug(" - method: $1");
        logger::debug(" - uri: $2");
        logger::debug(" - headers: $3");
        $$buf = "";
        delete $_st->{$conn_k1};
        delete $_st->{$conn_k2};
        return;
    }

    # was this a HTTP response? server -> client
    my $res = $st->{buf} =~ s{.*?HTTP/1\.\d\s(\d+)\s(.*?)\r\n(.*?)\r\n\r\n}{}ms;
    if($res){
        logger::debug("HTTP Response");
        logger::debug(" - status: $1");
        logger::debug(" - reason: $2");
        logger::debug(" - headers: $3");
        # let's parse the headers for Content-Length
        my $content_length = $3 =~ m{Content-Length:\s(\d+)}m;
        logger::debug(" - content_length: $content_length");
        # let's throw away the response body for now
        substr($$buf, 0, $content_length, '') if $content_length;
        if(length($$buf) > 0){
            logger::debug(" - remaining: ".length($$buf));
            logger::debug(" - remaining[hex]: ".to_hex($$buf));
        }
        delete $_st->{$conn_k1};
        delete $_st->{$conn_k2};
        return;
    }

    # is this a websocket frame?
    my $wsbuf = \($st->{wsbuf} //= "");
    logger::debug("check WEBSOCKET, $pkt->{conn}");
    while(length($$buf//"") > 1){
        logger::debug("buf: ".to_hex($$buf));
        my $frame_st = substr($$buf, 0, 1, '');
        logger::debug("frame header 1: ".to_hex($frame_st));
        my $fin_opcode = unpack("C", $frame_st);
        my $fin    = ($fin_opcode>>7) & 0x1;
        my $opcode = $fin_opcode & 0x0f;
        if($opcode == 0x01){
            logger::debug("text frame");
        } elsif($opcode == 0x02){
            logger::debug("binary frame");
        } elsif($opcode == 0x08){
            logger::debug("close frame");
        } elsif($opcode == 0x09){
            logger::debug("ping frame");
        } elsif($opcode == 0x0a){
            logger::debug("pong frame");
        } elsif($opcode == 0x00){
            logger::debug("non-first frame of fragmented message");
        } else {
            logger::debug("probably not websocket, opcode: ".to_hex(pack("C", $opcode)));
            return;
        }
        if(!length($$buf)){
            logger::debug("buffer empty");
            last;
        }
        $frame_st = substr($$buf, 0, 1, '');
        logger::debug("frame header 2: ".to_hex($frame_st));
        my $payload_len = unpack("C", $frame_st);
        my $masked = ($payload_len>>7) & 0x1;
        $payload_len &= 0x7f;
        if($payload_len == 126){
            $payload_len = unpack("S>", substr($$buf, 0, 2, ''));
            return unless defined $payload_len;
        } elsif($payload_len == 127){
            $payload_len = unpack("Q>", substr($$buf, 0, 8, ''));
            return unless defined $payload_len;
        } else {
        }
        logger::debug("fin: $fin, opcode: $opcode, mask: $masked, payload_len: $payload_len");
        my $mask_key;
        if($masked){
            $mask_key = substr($$buf, 0, 4, '');
        }
        my $masked_data = substr($$buf, 0, $payload_len, '');
        if(length($masked_data) < $payload_len){
            logger::debug("incomplete frame");
            return;
        }
        logger::debug("got data, size:".length($masked_data));
        if($opcode == 0x08){
            logger::debug("close frame");
            if(length($masked_data) >= 2){
                my $close_code = unpack("S>", substr($masked_data, 0, 2, ''));
                logger::debug("close_code: $close_code");
                my $close_reason = substr($masked_data, 0, length($masked_data), '');
                logger::debug("close_reason: $close_reason");
            } elsif(length($masked_data)){
                logger::debug("close frame, short data: ".length($masked_data)." bytes");
            }
            $$wsbuf = "";
            last;
        }
        if($masked and length($mask_key) >= 4){
            logger::debug("mask_key: ".to_hex($mask_key));
            logger::debug("masked_data: ".to_hex($masked_data));
            $masked_data ^= substr(($mask_key x (int(length($masked_data)/length($mask_key))+1)), 0, length($masked_data));
            logger::debug("unmask_data: ".to_hex($masked_data));
        } else {
            logger::debug("unmask_data: ".to_hex($masked_data));
        }
        if($fin == 0x01){
            $$wsbuf .= $masked_data;
            logger::debug("final frame");
            if($opcode == 0x02 or $opcode == 0x01){
                logger::debug("final binary frame");
                $h_sub //= sub {
                    my ($buffer_ref) = @_;
                    print $$buffer_ref."\n";
                    return;
                };
                &{$h_sub}($wsbuf, $pkt);
            } else {
                logger::debug("final frame");
                if($opcode == 0x0a or $opcode == 0x09){
                    logger::debug("ping/pong frame, payload for ping/pong: $masked_data");
                } else {
                    print $$wsbuf."\n";
                }
            }
            $$wsbuf = "";
        } else {
            if($opcode == 0x02 or $opcode == 0x01){
                logger::debug("continuation binary frame");
                $$wsbuf .= $masked_data;
            } else {
                logger::debug("continuation frame");
            }
        }
    }
    return;
}

sub to_hex {
    my $b = \$_[0];
    return join("",map {sprintf("%02x", ord $_)} split '', $$b//"");
}

sub xor_msg {
    my ($s_key8, $m) = @_;
    my $fs_key8 = substr(($s_key8) x (int(length($m)/length($s_key8))+1), 0, length($m));
    return $m ^ $fs_key8;
}

# ===========================================================================
# Inline logger - replaces utils::logger
# ===========================================================================
package logger;
use strict;
use warnings;

no warnings 'redefine';

our $_log_level;
our $_logger_stderr;

sub _cfg {
    my ($k, $default) = @_;
    my $env_m = "NETFILTER_" . uc($k);
    my $env_a = "XOR_" . uc($k);
    $ENV{$env_m} // $ENV{$env_a} // $default;
}

sub log_fatal {
    my (@msg) = @_;
    print STDERR "[FATAL] " . join(" ", @msg) . "\n";
    die join(" ", @msg) . "\n";
}

sub log_error {
    my (@msg) = @_;
    return unless _cfg("logger_level", 'info') =~ /^(error|info|debug)$/
                 || _cfg("DEBUG", 0);
    print STDERR "[ERROR] " . join(" ", @msg) . "\n";
}

sub log_info {
    my (@msg) = @_;
    return unless _cfg("logger_level", 'info') =~ /^(info|debug)$/
                 || _cfg("DEBUG", 0);
    print STDERR "[INFO] " . join(" ", @msg) . "\n";
}

sub log_debug {
    my (@msg) = @_;
    return unless _cfg("logger_level", 'info') =~ /^(debug)$/
                 || _cfg("DEBUG", 0);
    no warnings 'once';
    require Data::Dumper;
    local $Data::Dumper::Sortkeys = 1;
    local $Data::Dumper::Indent   = 0;
    local $Data::Dumper::Terse    = 1;
    local $Data::Dumper::Deepcopy = 1;
    print STDERR "[DEBUG] " . join(" ", map {ref($_) ? Data::Dumper::Dumper($_) : $_} @msg) . "\n";
}

# Aliases used by original logger
BEGIN { no warnings 'once'; *fatal = *log_fatal; *error = *log_error; *info = *log_info; *debug = *log_debug; }

# ===========================================================================
# Inline cfg - replaces utils::cfg
# ===========================================================================
package utils;
use strict;
use warnings;

no warnings 'redefine';

sub cfg {
    my ($k, $default, $nm, $do_exception, $r) = @_;
    my $env_m = uc("NETFILTER_$k");
    my $env_a = uc("XOR_$k");
    my $v = $ENV{$env_m} // $ENV{$env_a} // $default;
    return $v;
}
