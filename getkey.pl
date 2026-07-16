#!/usr/bin/env perl

use strict; use warnings;

use JSON;
use FindBin;

my $where = $FindBin::Bin;

# do we have a file?
my $tcpdump_fn = shift @ARGV;
die usage() unless $tcpdump_fn and -e $tcpdump_fn;

# read in tcpdump streams, in hex, add extra filters if needed:
#
#   -R '(tcp.stream eq 3 and websocket || http)'
#

open(my $t_fh, "tshark -r $tcpdump_fn -X lua_script:$where/ws.lua -T fields -e bcencrypt.hex|")
    or die "Error opening tshark: $!\n";
my @p;
while(my $l = <$t_fh>){
    chomp($l);
    next unless length($l);
    $l =~ s/(..)/pack("C", hex($1))/gems;
    push @p, $l;
}

# do we have data?
die usage() unless @p;

#
# Look for a message with 124 bytes, like this:
#
#   [2,"5","StatusNotification",{"connectorId":1,"status":"Available","errorCode":"NoError","timestamp":"2024-06-11T12:49:42Z"}]
#
# Or for 265 bytes, like this:
#   [2,"1","BootNotification",{"chargePointVendor":...]
#
# In theory, we can even pick the first 20 bytes and try multiple messages, the
# BootNotification message is the first one, but can be of variable length so
# we can't catch it because of a fixed size.
#
# Also note that the second array field is a uniqueRequestId, which is 1 byte,
# and this changes, it's 1 at BootNotification, but if we want to check other
# messages, we need to make that a bit more "strict"
#
# See also the OCPP 1.6j standard. Note that this expects the uniqueRequestId
# to be 1 byte (here: 5).
#

my $msg;
foreach my $data (@p){
    #print STDERR $data =~ s/(.)/sprintf("%02X",ord($1))/gesmr, "\n";
}
$msg = $_ for grep {length($_) == 265} @p;

my $boot_msg = [
    [  0, '['], # [2,"
    [  1, '2'],
    [  2, ','],
    [  3, '"'],

    [ 24, '"'], # ",{"
    [ 25, ','],
    [ 26, '{'],
    [ 27, '"'],

    [  8, 'B'], # Boot
    [  9, 'o'],
    [ 10, 'o'],
    [ 11, 't'],

    [ 12, 'N'], # Noti
    [ 13, 'o'],
    [ 14, 't'],
    [ 15, 'i'],

    [ 16, 'f'], # fica
    [ 17, 'i'],
    [ 18, 'c'],
    [ 19, 'a'],
];

my $sz_msg_decode_map = {
    22 => [
        [  0, '['],
        [  1, '2'],
        [  2, ','],
        [  3, '"'],

        [-18, '4'],
        [-17, '"'],

        [-16, ','],
        [-15, '"'],
        [-14, 'H'],
        [-13, 'e'],

        [-12, 'a'],
        [-11, 'r'],
        [-10, 't'],
        [ -9, 'b'],

        [ -8, 'e'],
        [ -7, 'a'],
        [ -6, 't'],
        [ -5, '"'],

        [ -4, ','],
        [ -3, '{'],
        [ -2, '}'],
        [ -1, ']'],
    ],
    124 => [
        [  0, '['],
        [  1, '2'],
        [  2, ','],
        [  3, '"'],

        [ 24, 'o'],
        [ 25, 'n'],
        [ 26, '"'],
        [ 27, ','],

        [-16, '-'],
        [  9, 't'],
        [ 10, 'a'],
        [-13, 'T'],

        [ 12, 'u'],
        [ 13, 's'],
        [ 14, 'N'],
        [ 15, 'o'],

        [ 16, 't'],
        [ 17, 'i'],
        [ 18, 'f'],
        [ 19, 'i'],
    ],
    265 => $boot_msg,
    28  => $boot_msg,
};

# find the XOR key
$msg //= "";
print STDERR "MSG[L:".length($msg)."]:".($msg =~ s/./sprintf("%02X",ord($&))/gesmr)."\n";
my $s_key8;
$s_key8 //= get_key($msg, $sz_msg_decode_map->{length($msg)});
my $decoded_msg;
my $err;
REDO:
    eval {
        die "No key found\n" unless $s_key8;
        $decoded_msg = xor_msg($s_key8, $msg);
        my $j_msg = JSON::decode_json($decoded_msg);
        print STDERR "DECODED: $decoded_msg\n";
    };
    if($@){
        print STDERR "ERROR: $@".(defined $decoded_msg?",DECODED MSG: $decoded_msg\n":"\n");
        $s_key8 = get_key(substr($msg, 0, 28), $boot_msg);
        $err = $@;
        goto REDO if $@ and !$err;
        die $@;
    }

# list as output
foreach my $m (@p){
    pr($m, $s_key8);
}

# print key
print STDERR "S8[".length($s_key8)."]: ".($s_key8 =~ s/./sprintf("%02X",unpack("C", $&))/gesmr).", KEY: ".($s_key8 =~ s/\W/./gsmr)."\n";
print "".($s_key8 =~ s/\W/./gsmr)."\n";
exit;

# FUNCTIONS

sub usage {
    return "usage: $0 <tcpdump file>\n";
}

sub bb {
    my ($w, $n, $what) = @_;
    return if abs($n) > length($w);
    my $t = substr($w, $n, 1);
    print STDERR "W: >>$w<< ->T\[$n\]: $t\n";
    return unless defined $t and length($t);
    my $r = unpack("C", $t);
    foreach my $k (0 .. 255){
        my $d = $r^$k;
        if(defined $d and chr($d) eq $what){
            return $k;
            last
        }
    }
    return;
}

sub get_key {
    my ($w, $km) = @_;
    my @kk;
    my $l = length($w);
    foreach my $kt (@$km){
        my $i = $l;
        if($kt->[0] < 0){
            $i += $kt->[0];
        } else {
            $i  = $kt->[0];
        }
        $i %= 20;
        print STDERR "I: $i\n";

        $kk[$i] //= bb($w, $kt->[0], $kt->[1]);
    }
    return pack("C*",map {$_//0} @kk);
}

sub xor_msg {
    my ($k, $m) = @_;
    my $fs_key8 = substr(($s_key8) x (int(length($m)/length($s_key8))+1), 0, length($m));
    return $m ^ $fs_key8;
}

sub pr {
    my ($m, $s_key8) = @_;
    my $fs_key8 = substr(($s_key8) x (int(length($m)/length($s_key8))+1), 0, length($m));
    print STDERR sprintf("%8s: %s\n", "K8",((($fs_key8 =~ s/\W/./gsmr))));
    print STDERR sprintf("%8s: %s\n", "U8[".length($m)."]", (($m ^ $fs_key8) =~ s/[^A-Za-z0-9_\-\"\{\}\[\],\.:]/./grms));
}

