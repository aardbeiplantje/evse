package pcap;

use strict;
use warnings;

sub pcap_decoder {
    my ($data_ref) = @_;

    # PCAP global header
    my $pcap_hdr = substr($$data_ref, 0, 24, '');
    return sub {
        return unless length($$data_ref) >= 16;
        my $pkt_hdr = substr($$data_ref, 0, 16, '');
        return unless length($pkt_hdr) == 16;

        # PCAP record header
        my ($ts_sec, $ts_usec, $incl_len, $orig_len) = unpack("LLLL", $pkt_hdr);

        # Ethernet header
        my $ethhdr = substr($$data_ref, 0, 14, '');
        my ($eth_dst, $eth_src, $eth_type) = unpack("a6a6S>", $ethhdr);

        # Ethernet type?
        if($eth_type == 0x0800){
            # IP
            my $pkt = substr($$data_ref, 0, $incl_len-14, '');
            return \$pkt;
        } elsif($eth_type == 0x0806){
            # ARP
        } else {
            # Unknown
        }
        return;
    };
}

1;
