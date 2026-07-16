#!/usr/bin/perl

# ===========================================================================
# Inline logger - replaces utils::logger
# ===========================================================================
package logger;
use strict;
use warnings;

our $_log_level;
our $_logger_stderr;
our $DEFAULT_LOGLEVEL = "info";

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
    return unless _cfg("logger_level", $DEFAULT_LOGLEVEL) =~ /^(error|info|debug)$/
                 || _cfg("DEBUG", 0);
    print STDERR "[ERROR] " . join(" ", @msg) . "\n";
}

sub log_info {
    my (@msg) = @_;
    return unless _cfg("logger_level", $DEFAULT_LOGLEVEL) =~ /^(info|debug)$/
                 || _cfg("DEBUG", 0);
    print STDERR "[INFO] " . join(" ", @msg) . "\n";
}

sub log_debug {
    my (@msg) = @_;
    return unless _cfg("logger_level", $DEFAULT_LOGLEVEL) =~ /^(debug)$/
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
{ no warnings 'once'; *fatal = *log_fatal; *error = *log_error; *info = *log_info; *debug = *log_debug; }

1;

# ===========================================================================
# Inline cfg - replaces utils::cfg
# ===========================================================================
package utils;
use strict;
use warnings;

sub cfg {
    my ($k, $default, $nm, $do_exception, $r) = @_;
    my $env_m = uc("NETFILTER_$k");
    my $env_a = uc("XOR_$k");
    my $v = $ENV{$env_m} // $ENV{$env_a} // $default;
    return $v;
}

1;

# ===========================================================================
# Main script
# ===========================================================================
package main;
use strict;
use warnings;

use FindBin qw($Bin);
use JSON::PP;

my $xor_key = $ENV{XOR_KEY};
my $where = $Bin;

# Determine input mode: pcap/tcpdump, trace, or raw websocket text
my $input_file = $ARGV[0] // $ENV{NF_PKT_TRACE} // "nf_pkt.trace";
my @packets;

if ($input_file =~ /\.(tcpdump|pcap|pcapng)$/i) {
    # pcap/tcpdump file - extract WebSocket text via tshark
    my $ws_lua = "$where/ws.lua";
    if ($xor_key) {
        # Encrypted: use ws.lua with XOR key
        open(my $t, "tshark -r $input_file -X lua_script1:$xor_key -X lua_script:$ws_lua -T fields -e bcencrypt.hex 2>/dev/null|grep --line-buffered .|")
            or die "Cannot run tshark: $!\n";
        while (my $l = <$t>) {
            chomp($l);
            next unless length($l);
            $l =~ s/(..)/pack("C", hex($1))/ge;
            push @packets, $l;
        }
        close($t);
    } else {
        # Plaintext: use built-in websocket payload text
        open(my $t, "tshark -r $input_file -Y websocket -T fields -e websocket.payload.text 2>/dev/null|grep --line-buffered .|")
            or die "Cannot run tshark: $!\n";
        while (my $l = <$t>) {
            chomp($l);
            next unless length($l);
            push @packets, $l;
        }
        close($t);
    }
    logger::info("Read " . scalar(@packets) . " websocket packets from $input_file");
} else {
    # Trace file: format is "L:<LENGTH>\n<DATA>" per packet
    # Each packet starts with a line like "L:12345" followed by exactly 12345 bytes of data
    open(my $fh, '<', $input_file) or die "Cannot open $input_file: $!\n";
    while (my $line = <$fh>) {
        chomp($line);
        next unless $line =~ /^L:(\d+)$/;
        my $len = $1;
        next unless $len > 0;
        my $data = '';
        my $got = 0;
        while ($got < $len) {
            my $ch = getc($fh);
            last unless defined $ch;
            $data .= $ch;
            $got++;
        }
        push @packets, $data if $got == $len;
    }
    close($fh);
    logger::info("Read " . scalar(@packets) . " packets from $input_file");
}

my $bc_state = {};
no warnings 'once';
my $st = {};

foreach my $raw_data (@packets) {
    # Feed raw TCP payload directly into handle_payload
    my $pkt = { data => $raw_data, conn => ['local', 'remote'] };
    handle_payload($st, $pkt, sub {
        my ($buffer_ref, $pkt) = @_;
        if ($xor_key) {
            handle_bc_payload($bc_state, $buffer_ref, $xor_key);
        } else {
            print $$buffer_ref;
            print STDERR join("->", @{$pkt->{conn}}) . ">>DATA>>$$buffer_ref<<\n";
            $$buffer_ref = "";
        }
        return;
    });
}

sub xor_msg {
    my ($s_key8, $m) = @_;
    my $fs_key8 = substr(($s_key8) x (int(length($m) / length($s_key8)) + 1), 0, length($m));
    return $m ^ $fs_key8;
}

sub handle_bc_payload {
    my ($state, $buffer_ref, $xor_key) = @_;
    my $decoded_msg = xor_msg($xor_key, $$buffer_ref);
    my $m;
    eval {
        $m = JSON::PP::decode_json($decoded_msg);
    };
    if ($@) {
        $m = undef;
    } else {
        if (!defined $m or ref($m) ne 'ARRAY') {
            $m = undef;
        }
    }
    my $power_used;
    my $meter_value = '';
    if ($m) {
        # this is an ocpp 1.6j message, let's check whether it's a start transaction
        if ($m->[2] =~ m/^(MeterValues|StartTransaction|StopTransaction)$/ and ref($m->[3]) eq 'HASH') {
            # get info from the message
            my $st = $m->[3];
            my $id_tag = $st->{idTag} // '';
            my $connector_id = $st->{connectorId} // 0;

            # get the metervalue from a udp/uart rs485 modbus call to an eastron SDM630, format:
            #   2025-05-31 22:45:23.652492,eastron:sdm630:totalkwh*kWh,1968.61193847656
            my $m_value = `LOGGER_STDERR=0 perl modbus.pl tcp://192.168.1.252:4196=1:Eastron::SDM630::TotalKWh`;
            if ($?) {
                $m_value = '';
            }
            if (length($m_value)) {
                chomp($m_value);
                if ($m_value =~ s{.*totalkwh\*kWh,}{}) {
                    if ($m_value =~ m{^(\d+(\.\d+)?)$}) {
                        $meter_value = $1;
                        my $power_cnt = \($state->{$id_tag . "/" . $connector_id} //= 0);
                        if ($m->[2] eq 'StartTransaction') {
                            $$power_cnt = $meter_value;
                            $power_used = 0;
                        }
                        if ($m->[2] eq 'StopTransaction') {
                            $power_used = $meter_value - $$power_cnt;
                        }
                        if ($m->[2] eq 'MeterValues') {
                            $power_used = $meter_value;
                        }
                    }
                }
            }
        }
    }
    if (defined $power_used) {
        print "$decoded_msg,$meter_value,$power_used\n";
    } else {
        print "$decoded_msg\n";
    }
    return;
}

sub handle_payload {
    my ($state, $pkt, $h_sub) = @_;
    return unless defined $pkt and defined $pkt->{data} and length($pkt->{data} // "");
    my $data_payload = $pkt->{data};
    my $conn_k1 = join(",", @{$pkt->{conn} // ['unknown']});
    my $conn_k2 = join(",", reverse @{$pkt->{conn} // ['unknown']});
    my $st = $state->{$conn_k1} //= $state->{$conn_k2} //= {};
    $st->{buf} //= "";
    $st->{buf} .= $data_payload;
    my $buf = \$st->{buf};

    # WebSocket frame parsing - peek first, only consume if valid
    my $wsbuf = \($st->{wsbuf} //= "");
    while (length($$buf // "") >= 2) {
        # Peek first byte to check opcode
        my $fin_opcode = unpack("C", substr($$buf, 0, 1));
        my $fin = ($fin_opcode >> 7) & 0x1;
        my $opcode = $fin_opcode & 0x0f;
        # accept only valid websocket opcodes
        last unless $opcode == 0x00 or $opcode == 0x01 or $opcode == 0x02
                 or $opcode == 0x08 or $opcode == 0x09 or $opcode == 0x0a;
        # Now consume frame header bytes
        substr($$buf, 0, 1, '');  # FIN+opcode
        my $payload_len = unpack("C", substr($$buf, 0, 1, ''));  # payload length byte
        my $masked = ($payload_len >> 7) & 0x1;
        $payload_len &= 0x7f;
        if ($payload_len == 126) {
            $payload_len = unpack("S>", substr($$buf, 2, 2, ''));
            return unless defined $payload_len;
        } elsif ($payload_len == 127) {
            $payload_len = unpack("Q>", substr($$buf, 2, 8, ''));
            return unless defined $payload_len;
        }
        my $mask_key;
        if ($masked) {
            $mask_key = substr($$buf, 0, 4, '');
        }
        my $masked_data = substr($$buf, 0, $payload_len, '');
        if (length($masked_data) < $payload_len) {
            return;
        }
        if ($opcode == 0x08) {
            $$wsbuf = "";
            last;
        }
        if ($masked and length($mask_key) >= 4) {
            $masked_data ^= substr(($mask_key x (int(length($masked_data) / length($mask_key)) + 1)), 0, length($masked_data));
        }
        if ($fin == 0x01) {
            $$wsbuf .= $masked_data;
            if ($opcode == 0x02 or $opcode == 0x01) {
                &{$h_sub}($wsbuf, $pkt);
            } else {
                print $$wsbuf . "\n" if $opcode != 0x0a and $opcode != 0x09;
            }
            $$wsbuf = "";
        } else {
            $$wsbuf .= $masked_data if $opcode == 0x02 or $opcode == 0x01;
        }
    }
    if (length($$buf)) {
        $h_sub //= sub {
            my ($buffer_ref) = @_;
            print $$buffer_ref . "\n";
            $$buffer_ref = "";
            return;
        };
        &{$h_sub}($buf, $pkt);
    }
    return;
}
