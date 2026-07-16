package sensor::netfilter_queue;

# This sensor is a netfilter queue sensor
# use strict doesn't work, inheritance breaks, TODO: verify
## no critic (RequireUseStrict, RequireUseWarnings)
#use strict;
use warnings;
use base qw(sensor);

use Socket qw(AF_INET SOCK_RAW);
use POSIX ();
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use File::Basename qw(dirname);
use File::Path qw(mkpath);
use FindBin;

use utils::netlink qw(AF_NETLINK NETLINK_NETFILTER NF_ACCEPT SOL_NETLINK NETLINK_EXT_ACK NETLINK_CAP_ACK NETLINK_NO_ENOBUFS);
use utils::ip_packet;
use utils::metrics;

sub sensor_init {
    my ($self) = @_;
    delete $self->{_socket};
    delete $self->{_fd};
    delete $self->{_bind_addr};
    $self->{_outbuffer} = "";

    my $queue_num = $self->{cfg}{l}{nf_queue_num} // $self->{cfg}{b} // 121;
    logger::log_info("queue_num: $queue_num");
    my $my_id = 0;#$$;
    my $bind_addr = pack("SSLL", AF_NETLINK, 0, $my_id, 0);
    my $nf_fh;
    logger::log_info("doing as root $< $> $( $)");
    utils::sudo_su_root(sub {
        logger::log_info("as root? $< $> $( $)");
        socket($nf_fh, AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)
            // die "socket: $!";
        bind($nf_fh, $bind_addr)
            // die "bind: $!";
        binmode($nf_fh);
        my $s_flags = fcntl($nf_fh, F_GETFL, 0)
            or die "Can't get flags for the socket: $!";
        fcntl($nf_fh, F_SETFL, $s_flags|O_NONBLOCK)
            or die "Can't set flags for the socket: $!";
        setsockopt($nf_fh, SOL_NETLINK, NETLINK_EXT_ACK, 0)
            or die "setsockopt: $!";
        setsockopt($nf_fh, SOL_NETLINK, NETLINK_CAP_ACK, 0)
            or die "setsockopt: $!";
        setsockopt($nf_fh, SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)
            or die "setsockopt: $!";
    });
    logger::log_info("drop privileges back $< $> $( $)");

    $self->{_bind_addr} = $bind_addr;
    $self->{_socket} = $nf_fh;
    $self->{_fd}     = fileno($nf_fh);

    # register for packets from the queue, $queue_num
    my $f_req = '';
    $f_req .= netlink::nfqnl_bind(AF_INET, $queue_num);
    $f_req .= netlink::nfqnl_copy_packet($queue_num, 0xffff); # full size copy
    $self->{_outbuffer} = $f_req;

    return $self->{_fd};
}

sub sensor_stop {
    my ($self) = @_;
    close($self->{_socket}) if defined $self->{_socket};
    delete $self->{_socket};
    delete $self->{_fd};
    return;
}

sub need_write {
    my ($self) = @_;
    return 1 if length($self->{_outbuffer});
    return 0;
}

sub handle_data {
    my ($self, $data) = @_;
    return unless length($data//"");
    # process the netlink/netfilter/queue message
    my $xor_key = $self->{cfg}{l}{xor_key};
    eval {
        my $st = \($self->{_nf_state} //= {});
        my $queue_num = $self->{cfg}{l}{nf_queue_num} // $self->{cfg}{b} // 121;
        logger::info("handling data from queue $queue_num:", to_hex($data));
        netlink::handle_nlmsg(\$data, sub {
            my ($ip_pkt_ref, $pkt_id, $m_seq) = @_;

            # always a positive verdict ACCEPT
            logger::info("sending verdict ACCEPT for packet $pkt_id, $m_seq, queue: $queue_num, id: 0");
            $self->{_outbuffer} .= netlink::nfqnl_msg_verdict($m_seq, 0, $queue_num, $pkt_id, NF_ACCEPT());
            $self->do_write();

            # process IP packet
            my $p_data = ip_packet::decode($ip_pkt_ref);
            logger::info("payload", length($p_data->{data}//"")?to_hex($p_data->{data}):"");

            # process IP packet data
            handle_ip_data($st, $p_data, sub {
                my ($buffer_ref) = @_;
                # valid HTTP/WebSocket data
                if($xor_key){
                    # XOR decode
                    logger::debug("xor_key: $xor_key");
                    my $decoded_msg = xor_msg($xor_key, $$buffer_ref);
                    logger::info("decoded_msg: $decoded_msg");

                    # JSON Parse
                    $self->ocpp_msg_process($decoded_msg);
                } else {
                    logger::info("ocpp msg: $$buffer_ref");
                    $self->ocpp_msg_process($$buffer_ref);
                }
                return;
            });
        });
    };
    if($@){
        logger::log_error("problem handling data: $@");
    }
    return;
}

sub log_data {
    my ($self, $msg) = @_;
    my $kv  = $self->{cfg}{k};
    my $bd  = $self->{cfg}{l}{data_dir}
        // utils::cfg("VARDIR", "/var/metrics");
    my $ofn = $self->{cfg}{l}{output}
        // POSIX::strftime("${bd}/${kv}/snoop_${kv}_%F.log", gmtime());
    my $of = do {
        local $!;
        my $bbd = dirname($ofn);
        if($bbd){
            eval {mkpath($bbd)};
            if($@){
                logger::error("problem creating dir $bbd: $@");
            }
        }
        my $_ofh;
        if(!open($_ofh, '>>', $ofn)){
            logger::error("problem opening $ofn: $!");
            open($_ofh, '>>', '&STDOUT') or
            open($_ofh, '>>', '/dev/null');
        }
        $_ofh;
    };
    print {$of} $msg."\n";
    close($of) or do {
        logger::error("problem closing $ofn: $!");
        print $msg."\n";
    };
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
            $self->log_data("$msg,$meter_value");
        } else {
            $self->log_data($msg);
        }

        # cool charging bool flag per idTag
        eval {
            my $idTag = $ocpp_msg->[3]{idTag};
            if      ($ocpp_msg->[2] eq "StartTransaction"){
                metrics::log_metric("blinkcharging:$self->{cfg}{k}:$idTag:charging,1");
            } elsif ($ocpp_msg->[2] eq "StopTransaction"){
                metrics::log_metric("blinkcharging:$self->{cfg}{k}:$idTag:charging,0");
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
    return unless defined $pkt and defined $pkt->{conn};
    my $_st = $$state //= {};
    logger::debug("handle payload");

    my $conn_k1 = join(",", @{$pkt->{conn}});
    my $conn_k2 = join(",", reverse @{$pkt->{conn}});

    # if we get a TCP_FIN or RST, close the connection and cleanup
    if(defined $pkt->{tcp_flags}){
        if($pkt->{tcp_flags} & 0x01 or $pkt->{tcp_flags} & 0x04){
            logger::debug("TCP_FIN/RST for ".join(",", @{$pkt->{conn}}));
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

    # skip non-TCP data
    return unless $pkt->{is_tcp};

    # skip TCP retransmissions (same seq_num + data length)
    my $seq_key = defined $pkt->{seq_num}
        ? join(":", $pkt->{seq_num}, length($pkt->{data}//""))
        : "";
    if($seq_key and defined $_st->{seen} and exists $_st->{seen}->{$seq_key}){
        logger::debug("retransmission skipped seq=$seq_key");
        return;
    }
    $_st->{seen} //= {};
    $_st->{seen}->{$seq_key} = 1 if $seq_key;

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

sub do_write {
    my ($self) = @_;
    return unless defined $self->{_outbuffer};
    my $n = length($self->{_outbuffer});
    logger::debug(">>WRITE>>$n>>".join('', map {sprintf '%04X', ord} split //, $self->{_outbuffer}));
    utils::sudo_su_root(sub {
        local $!;
        my $r = send($self->{_socket}, $self->{_outbuffer}, 0, $self->{_bind_addr});
        if($!){
            return if $!{EINTR} or $!{EAGAIN};
            die "problem writing data [fd:$self->{_fd}]: $!\n";
        }
        $self->{_outbuffer} = "";
    });
    return;
}

sub do_read {
    my ($self) = @_;
    no warnings 'once';
    while($::METRICS::LOOP){
        # read
        my $pkt_msg;
        my ($r) = utils::sudo_su_root(sub {
            local $!;
            my $r = recv($self->{_socket}, $pkt_msg, 131072, 0);
            if(!defined $r){
                return 1 if $!{EINTR} or $!{EAGAIN};
                die "problem reading data [fd:$self->{_fd},key:$self->{cfg}{k}]: $!\n";
            }
            return 0;
        });
        return 1 if $r;

        # ok data, handle it
        $self->handle_data($pkt_msg);
    }
    return 1;
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

1;
