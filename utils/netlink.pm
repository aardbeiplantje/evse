package netlink;

package utils::netlink;

use strict; use warnings;
use base qw(Exporter);

our @EXPORT_OK = ();
our @EXPORT    = ();
our @EXPORT_CONSTANTS = qw(
    AF_NETLINK
    NETLINK_NETFILTER
    SOL_NETLINK
    NETLINK_CAP_ACK
    NETLINK_EXT_ACK
    NETLINK_GET_STRICT_CHK
    NF_DROP
    NF_ACCEPT
    NF_STOLEN
    NF_QUEUE
    NF_REPEAT
    NETLINK_ADD_MEMBERSHIP
    NETLINK_DROP_MEMBERSHIP
    NETLINK_PKTINFO
    NETLINK_BROADCAST_ERROR
    NETLINK_NO_ENOBUFS
    NETLINK_LISTEN_ALL_NSID
    NETLINK_LIST_MEMBERSHIPS
);

sub import {
	my ($class, @lst) = @_;
	foreach my $_m (@EXPORT_CONSTANTS){     
		next unless grep {$_m eq $_} @lst;
    	my $pkg = caller;     
		no strict 'refs';     
		*{"${pkg}::${_m}"} = \&{"netlink::${_m}"};
	}     
	return;
}

package netlink;

use strict; use warnings;

use utils::logger;

sub AF_NETLINK        {16};
sub NETLINK_NETFILTER {12};
sub SOL_NETLINK       {270};

sub NF_DROP    {0};
sub NF_ACCEPT  {1};
sub NF_STOLEN  {2};
sub NF_QUEUE   {3};
sub NF_REPEAT  {4};

sub NETLINK_CAP_ACK          {10};
sub NETLINK_EXT_ACK          {11};
sub NETLINK_GET_STRICT_CHK   {12};

sub NETLINK_ADD_MEMBERSHIP   {1};
sub NETLINK_DROP_MEMBERSHIP  {2};
sub NETLINK_PKTINFO          {3};
sub NETLINK_BROADCAST_ERROR  {4};
sub NETLINK_NO_ENOBUFS       {5};
sub NETLINK_LISTEN_ALL_NSID  {8};
sub NETLINK_LIST_MEMBERSHIPS {9};

our $AF_UNSPEC = 0;

our $NETLINK_TAX_NONE   = 0x00000000;  # NETLINK_TAX_NONE
our $NETLINK_TAX_NET    = 0x00000001;  # NETLINK_TAX_NET
our $NETLINK_TAX_INET   = 0x00000002;  # NETLINK_TAX_INET
our $NFNL_SUBSYS_QUEUE  = 3;

our $NFNETLINK_V0 = 0;

our $NFQNL_MSG_PACKET        = 0;
our $NFQNL_MSG_VERDICT       = 1;
our $NFQNL_MSG_CONFIG        = 2;
our $NFQNL_MSG_VERDICT_BATCH = 3;

our $NFQNL_CFG_CMD_NONE      = 0;
our $NFQNL_CFG_CMD_BIND      = 1;
our $NFQNL_CFG_CMD_UNBIND    = 2;
our $NFQNL_CFG_CMD_PF_BIND   = 3;
our $NFQNL_CFG_CMD_PF_UNBIND = 4;

our $NFQNL_COPY_NONE    = 0;
our $NFQNL_COPY_META    = 1;
our $NFQNL_COPY_PACKET  = 2;

our $NFQA_CFG_UNSPEC       = 0;
our $NFQA_CFG_CMD          = 1;
our $NFQA_CFG_PARAMS       = 2;
our $NFQA_CFG_QUEUE_MAXLEN = 3;
our $NFQA_CFG_MASK         = 4;
our $NFQA_CFG_FLAGS        = 5;

our $NFQA_CFG_F_FAIL_OPEN = 0x01;
our $NFQA_CFG_F_CONNTRACK = 0x02;
our $NFQA_CFG_F_GSO       = 0x04;
our $NFQA_CFG_F_UID_GID   = 0x08;
our $NFQA_CFG_F_SECCTX    = 0x16;
our $NFQA_CFG_F_MAX       = 0x32;

# GENERIC Flags
our $NLM_F_REQUEST       = 0x01;
our $NLM_F_MULTI         = 0x02;
our $NLM_F_ACK           = 0x04;
our $NLM_F_ECHO          = 0x08;
our $NLM_F_DUMP_INTR     = 0x10;
our $NLM_F_DUMP_FILTERED = 0x20;

# MODIFIERS for GET request
our $NLM_F_ROOT          = 0x100;
our $NLM_F_MATCH         = 0x200;
our $NLM_F_ATOMIC        = 0x400;
our $NLM_F_DUMP          = $NLM_F_ROOT | $NLM_F_MATCH;

# MODIFIERS for NEW request
our $NLM_F_REPLACE       = 0x100;
our $NLM_F_EXCL          = 0x200;
our $NLM_F_CREATE        = 0x400;
our $NLM_F_APPEND        = 0x800;

# MODIFIERS for DELETE request
our $NLM_F_NONREC        = 0x100;

# Flags for ACK message
our $NLM_F_CAPPED        = 0x40;
our $NLM_F_ACK_TLVS      = 0x80;

our $NFQA_PACKET_HDR         = 1;
our $NFQA_VERDICT_HDR        = 2;
our $NFQA_MARK               = 3;
our $NFQA_TIMESTAMP          = 4;
our $NFQA_IFINDEX_INDEV      = 5;
our $NFQA_IFINDEX_OUTDEV     = 6;
our $NFQA_IFINDEX_PHYSINDEV  = 7;
our $NFQA_IFINDEX_PHYSOUTDEV = 8;
our $NFQA_HWADDR             = 9;
our $NFQA_PAYLOAD            = 10;
our $NFQA_CT                 = 11;
our $NFQA_CT_INFO            = 12;
our $NFQA_CAP_LEN            = 13;
our $NFQA_SKB_INFO           = 14;
our $NFQA_EXP                = 15;
our $NFQA_UID                = 16;
our $NFQA_GID                = 17;
our $NFQA_SECCTX             = 18;
our $NFQA_VLAN               = 19;
our $NFQA_L2HDR              = 20;


our $NLMSG_NOOP    = 1;
our $NLMSG_ERROR   = 2;
our $NLMSG_DONE    = 3;
our $NLMSG_OVERRUN = 4;



sub nfqnl_send {
    my ($nf_fh, $tgt_addr, @cmds) = @_;
    foreach my $msg (@cmds){
        send($nf_fh, $msg, 0, $tgt_addr);
        if($!){
            return;
        }
    }
    return !$!;
}

sub nfqnl_bind {
    my ($pf_family, $res_id) = @_;
    my $m_hdr = nlmsghdr($NFNL_SUBSYS_QUEUE<<8|$NFQNL_MSG_CONFIG, $NLM_F_REQUEST);
    my $p_hdr = genlmsghdr($AF_UNSPEC, $NFNETLINK_V0, $res_id);
    return nlmsg($m_hdr, $p_hdr,
        nlattr($NFQA_CFG_CMD, nfqnl_msg_config_cmd($NFQNL_CFG_CMD_BIND, $pf_family))
    );
}

sub nfqnl_copy_packet {
    my ($res_id, $pkt_size) = @_;
    $pkt_size //= 0xffff;
    my $m_hdr = nlmsghdr($NFNL_SUBSYS_QUEUE<<8|$NFQNL_MSG_CONFIG, $NLM_F_REQUEST);
    my $p_hdr = genlmsghdr($AF_UNSPEC, $NFNETLINK_V0, $res_id);
    return nlmsg($m_hdr, $p_hdr,
        nlattr($NFQA_CFG_PARAMS, pack("L>C", $pkt_size, $NFQNL_COPY_PACKET)),
        nlattr($NFQA_CFG_FLAGS, pack("L>", $NFQA_CFG_F_GSO)),
        nlattr($NFQA_CFG_MASK, pack("L>", $NFQA_CFG_F_GSO)),
    );
}

sub nfqnl_msg_verdict {
    my ($nl_seq, $nl_pid, $res_id, $pkt_id, $verdict) = @_;
    my $m_hdr = nlmsghdr($NFNL_SUBSYS_QUEUE<<8|$NFQNL_MSG_VERDICT, $NLM_F_REQUEST, $nl_seq, $nl_pid);
    my $p_hdr = genlmsghdr($AF_UNSPEC, $NFNETLINK_V0, $res_id);
    return nlmsg($m_hdr, $p_hdr,
        nlattr($NFQA_VERDICT_HDR, pack("L>L>", $verdict, $pkt_id)),
    );
}

sub nlmsg {
    my ($m_hdr, $p_hdr, @nlattr) = @_;
    my $t_msg = $m_hdr.$p_hdr;
    $t_msg .= "\0" x (length($t_msg) % 4 ?4 - length($t_msg) % 4: 0);
    foreach my $nlattr (@nlattr){
        $t_msg .= $nlattr;
        $t_msg .= "\0" x (length($t_msg) % 4 ?4 - length($t_msg) % 4: 0);
    }
    return pack("L<a*", length($t_msg)+4, $t_msg);
}

sub nfqnl_msg_config_cmd {
    my ($cmd, $pf) = @_;
    return pack("CCS>", $cmd, 0, $pf);
}

sub genlmsghdr {
    my ($nf_family, $version, $res_id) = @_;
    return pack("CCS>", $nf_family, $version, $res_id);
}

sub nlattr {
    my ($nla_type, $data) = @_;
    my $tlv = pack("SSa*", length($data)+4, $nla_type, $data);
    $tlv .= "\0" x (length($tlv) % 4 ?4 - length($tlv) % 4: 0);
    return $tlv;
}

sub nlmsghdr {
    my ($nl_type, $nl_flags, $nl_seq, $nl_pid) = @_;
    $nl_flags //= 0;
    $nl_seq   //= 0;
    $nl_pid   //= 0; # some ID?
    return pack("SSLL", $nl_type, $nl_flags, $nl_seq, $nl_pid);
}

sub handle_nlmsg {
    my ($msg_ref, $data_cb_sub) = @_;
    my ($len, $type, $flags, $seq, $pid) = unpack("LSSLL", substr($$msg_ref, 0, 16,''));
    logger::debug("MSG[".length($$msg_ref)."]: len: $len, type: $type, flags: $flags, seq: $seq, pid: $pid");
    if($type == $NLMSG_ERROR){
        # parse the NETLINK error message
        my ($err_num, $e_msg) = unpack("l>a*", $$msg_ref);
        logger::debug("ERROR[$err_num]: 0x".to_hex($$msg_ref));
        $! = -$err_num;
        die "ERROR[$err_num]: $!\n";
    }
    if($type == $NLMSG_OVERRUN){
        logger::debug("OVERRUN");
        return;
    }
    if($type == $NLMSG_NOOP){
        logger::debug("NOOP");
        return;
    }
    if($flags & $NLM_F_ACK){
        logger::debug("ACK");
        return;
    }
    if($type == $NLMSG_DONE){
        logger::debug("DONE");
        return;
    }
    my $ret;
    if($type == ($NFNL_SUBSYS_QUEUE<<8|$NFQNL_MSG_PACKET)){
        $ret = handle_nfqnl_msg_packet($msg_ref, $data_cb_sub, $seq);
    } else {
        logger::debug("ERROR: Unknown message type: $type");
    }
    return $seq, $pid, $ret;
}

sub handle_nfqnl_msg_packet {
    my ($data_ref, $data_cb_sub, $seq) = @_;
    my ($gen_hdr_nf_family, $gen_hdr_nf_version, $gen_hdr_nf_res_id)
        = unpack("CCS>", substr($$data_ref, 0, 4, ''));
    logger::debug("gen_hdr_nf_family: $gen_hdr_nf_family");
    logger::debug("gen_hdr_nf_version: $gen_hdr_nf_version");
    logger::debug("queue_number $gen_hdr_nf_res_id");
    my $nl_attrs = $data_ref;
    my @pkt_ids;
    my $packet_id;
    while(length($$nl_attrs) > 0){
        logger::debug(" hex: ".to_hex($$nl_attrs)."");
        my ($nla_len, $nla_type) = unpack("SS", $$nl_attrs);
        my $nr_pad = $nla_len % 4 ?4 - $nla_len % 4: 0;
        my $nla_data = substr($$nl_attrs, 0, $nla_len, '');
        substr($nla_data, 0, 4, '');
        logger::debug(" nr_pad: $nr_pad");
        logger::debug(" nla_type: $nla_type");
        logger::debug(" nla_len: $nla_len");
        logger::debug(" nla_data: ".to_hex($nla_data)."");
        logger::debug(" remaining: ".length($$nl_attrs)."");
        if($nla_type == $NFQA_PACKET_HDR){
            ($packet_id, my $hw_protocol, my $hook) = unpack("L>S>C", $nla_data);
            logger::debug(" - packet_id: $packet_id");
            logger::debug(" - hw_protocol: $hw_protocol");
            logger::debug(" - hook: $hook");
            push @pkt_ids, $packet_id;
        } elsif($nla_type == $NFQA_HWADDR){
            my ($hw_addrlen, $pad) = unpack("S>S", $nla_data);
            my $hw_addr = substr($nla_data, 0, $hw_addrlen, '');
            logger::debug(" - hw_addrlen: $hw_addrlen");
            logger::debug(" - hw_addr: ".to_hex($hw_addr)."");
        } elsif($nla_type == $NFQA_TIMESTAMP){
            my ($sec, $usec) = unpack("Q>Q>", $nla_data);
            logger::debug(" - sec: $sec");
            logger::debug(" - usec: $usec");
        } elsif($nla_type == $NFQA_IFINDEX_INDEV){
            my $ifindex = unpack("L>", $nla_data);
            logger::debug(" - ifindex: $ifindex");
        } elsif($nla_type == $NFQA_IFINDEX_OUTDEV){
            my $ifindex = unpack("L>", $nla_data);
            logger::debug(" - ifindex: $ifindex");
        } elsif($nla_type == $NFQA_IFINDEX_PHYSINDEV){
            my $ifindex = unpack("L>", $nla_data);
            logger::debug(" - ifindex: $ifindex");
        } elsif($nla_type == $NFQA_IFINDEX_PHYSOUTDEV){
            my $ifindex = unpack("L>", $nla_data);
            logger::debug(" - ifindex: $ifindex");
        } elsif($nla_type == $NFQA_PAYLOAD){
            logger::debug(" - payload[hex]: ".to_hex($nla_data)."");
            if(defined $data_cb_sub and ref($data_cb_sub) eq "CODE"){
                &{$data_cb_sub}(\$nla_data, $packet_id, $seq);
            }
        } elsif($nla_type == $NFQA_CT){
            logger::debug(" - conntrack[hex]: ".to_hex($nla_data)."");
        } elsif($nla_type == $NFQA_CT_INFO){
            logger::debug(" - conntrack_info[hex]: ".to_hex($nla_data)."");
        } elsif($nla_type == $NFQA_MARK){
            my $mark = unpack("L>", $nla_data);
            logger::debug(" - mark: $mark");
        } elsif($nla_type == $NFQA_VLAN){
            my ($vlan_tci, $vlan_proto) = unpack("S>S>", $nla_data);
            logger::debug(" - vlan_tci: $vlan_tci");
            logger::debug(" - vlan_proto: $vlan_proto");
        } elsif($nla_type == $NFQA_L2HDR){
            logger::debug(" - l2hdr[hex]: ".to_hex($nla_data)."");
        } elsif($nla_type == $NFQA_EXP){
            logger::debug(" - exp[hex]: ".to_hex($nla_data)."");
        } elsif($nla_type == $NFQA_UID){
            my $uid = unpack("L>", $nla_data);
            logger::debug(" - uid: $uid");
        } elsif($nla_type == $NFQA_GID){
            my $gid = unpack("L>", $nla_data);
            logger::debug(" - gid: $gid");
        } elsif($nla_type == $NFQA_SECCTX){
            logger::debug(" - secctx[hex]: ".to_hex($nla_data)."");
        } elsif($nla_type == $NFQA_SKB_INFO){
            logger::debug(" - skb_info[hex]: ".to_hex($nla_data)."");
        } else {
            logger::debug(" - unknown $nla_type");
        }
        substr($$nl_attrs, 0, $nr_pad, '');
    }
    return \@pkt_ids;
}

sub to_hex {
    my $b = \$_[0];
    return join("",map {sprintf("%02x", ord $_)} split '', $$b//"");
}


1;
