package logger;

use strict; use warnings;

use utils::cfg;

our $_json_printer;
our $_init_syslog;
our $_syslog_logger;

$::DEFAULT_LOGLEVEL = "info";

*fatal = *log_fatal;
*error = *log_error;
*info  = *log_info;
*debug = *log_debug;

sub log_fatal {
    my (@msg) = @_;
    my $msg = do_log("error", @msg);
    die "$msg\n";
}

sub log_error {
    my (@msg) = @_;
    return unless lc(utils::cfg("logger_level", $::DEFAULT_LOGLEVEL)) =~ m/^(error|info|debug)$/
                    || utils::cfg("DEBUG", 0);
    return do_log("error", @msg);
}

sub log_info {
    my (@msg) = @_;
    return unless lc(utils::cfg("logger_level", $::DEFAULT_LOGLEVEL)) =~ m/^(info|debug)$/
                    || utils::cfg("DEBUG", 0);
    return do_log("info", @msg);
}

sub log_debug {
    my (@msg) = @_;
    return unless lc(utils::cfg("logger_level", $::DEFAULT_LOGLEVEL)) =~ m/^(debug)$/
                    || utils::cfg("DEBUG", 0);
    no warnings 'once';
    require Data::Dumper;
    local $Data::Dumper::Sortkeys = 1;
    local $Data::Dumper::Indent   = 0;
    local $Data::Dumper::Terse    = 1;
    local $Data::Dumper::Deepcopy = 1;
    return do_log("debug", map {ref($_)?Data::Dumper::Dumper($_):$_} @msg);
}

sub do_log {
    my ($w, @msg) = @_;
    require POSIX;
    require Time::HiRes;
    local $::LOG_PREFIX = $::LOG_PREFIX // "";
    @msg =
        map {split m/\n/, $_//""}
        join("",
        map {defined $_ and ref($_)
            ?do {
                $_ = eval {
                    require JSON;
                    $_json_printer //= JSON->new->canonical->allow_nonref->allow_unknown->allow_blessed->convert_blessed->allow_tags->indent(0);
                    $_json_printer->encode($_);
                };
                $_//"";
            }
            :$_//""
        } @msg);
    if(utils::cfg("logger_stderr", -t STDIN)){
        my ($tm, $usec) = Time::HiRes::gettimeofday();
        $usec = sprintf("%06d", $usec);
        my @tm = localtime($tm);
        my $msg = join("\n", map {POSIX::strftime("%H:%M:%S.$usec", @tm)." [$$] [$w]: $::LOG_PREFIX$_"} map {split m/\n/, $_//""} @msg);
        print STDERR "$msg\n";
    }
    if(!$_init_syslog and my $tgt = utils::cfg("logger_syslog")){
        $tgt = "unix:///dev/log" if $tgt eq '1';
        require Socket;
        require Fcntl;
        if($tgt !~ m/^(udp|unix):\/\/(.*?)(?::(\d+))?$/i){
            $_init_syslog = 1;
        } else {
            my ($s, $t_addr);
            my $tgt_sink_scheme   = $1;
            my $tgt_udp_sink_host = $2;
            my $tgt_udp_sink_port = $3;
            if($tgt_sink_scheme eq 'udp'){
                my $h_addr = inet_aton($tgt_udp_sink_host)
                    // die "unknown host: $tgt_udp_sink_host";
                $t_addr = sockaddr_in($tgt_udp_sink_port, $h_addr);
                my $proto  = getprotobyname("udp");
                socket($s, Socket::PF_INET(), Socket::SOCK_DGRAM(), $proto)
                    // die "socket create problem: $!\n";
            } elsif($tgt_sink_scheme eq 'unix'){
                $t_addr = Socket::pack_sockaddr_un($tgt_udp_sink_host);
                socket($s, Socket::PF_UNIX(), Socket::SOCK_DGRAM(), 0)
                    // die "socket create problem: $!\n";
            }
            fcntl($s, Fcntl::F_SETFL(), Fcntl::O_RDWR()|Fcntl::O_NONBLOCK())
                // die "socket non-blocking set problem: $!\n";
            binmode($s)
                // die "binmode problem: $!\n";
            my $syslog_facility = 20<<3; # LOG_LOCAL4
            my $syslog_level    = 7;     # DEBUG
            my $syslog_priv = "<".($syslog_facility + $syslog_level).">";
            $_syslog_logger = sub {
                my (@m_data) = @_;
                # split, recombine and send
                my @m = split m/\n/, join("\n", @m_data);
                while(my $next_m = shift @m){
                    my @tm = localtime();
                    my $dt = POSIX::strftime("%b %d %H:%M:%S", @tm);
                    $next_m = "$syslog_priv$dt ${0}[$$]: $::LOG_PREFIX$next_m\n";
                    send($s, $next_m, 0, $t_addr);
                }
            };
            $_init_syslog = 1;
        }
    }
    &{$_syslog_logger}(@msg) if defined $_syslog_logger and @msg;
    return;
}

package log;

use strict; use warnings;
use base qw(logger);

1;
