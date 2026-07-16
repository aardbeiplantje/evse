package utils;

use strict; use warnings;

sub cfg {
    my ($k, $default_v, $nm, $do_exception, $r) = @_;
    no warnings 'once';
    $nm //= $::APP_MODULE // "";
    my $env_k_m = ($::APP_NAME//"")."_${nm}_$k";
    my $env_k_a = ($::APP_NAME//"")."_$k";
    my $v = ($r and UNIVERSAL::can($r, "variable") and $r->variable(lc($env_k_a)))
        // $::APP_ENV{uc($env_k_m) =~ s/\W/_/gr}
        // $::APP_ENV{uc($env_k_a) =~ s/\W/_/gr}
        // $::APP_CFG->{uc($env_k_m)}
        // $::APP_CFG->{uc($env_k_a)}
        // $::APP_CFG->{$k}
        // $ENV{uc($env_k_m) =~ s/\W/_/gr}
        // $ENV{uc($env_k_a) =~ s/\W/_/gr}
        // $default_v;
    die "need '$k' config or $env_k_m/$env_k_a ENV variable\n" if $do_exception and not defined $v;
    return $v;
}

sub set_cfg {
    my ($k, $v) = @_;
    my $env_k_a = ($::APP_NAME//"")."_$k";
    $::APP_CFG->{$env_k_a} = $v;
    return $v;
}

1;
