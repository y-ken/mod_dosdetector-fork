#!/usr/bin/perl
use strict;
use warnings;
use Fatal qw/open close/;

my $apache20dir = shift;
unless(defined($apache20dir) && -d $apache20dir) {
    print "$0 <path/to/httpd-2.2.x>\n";
    exit;
}

my $mod_dosdetector_c = "./mod_dosdetector.c";
my $shm_c = "$apache20dir/srclib/apr/shmem/unix/shm.c";
my $start_apr_shm_remove = qr/^APR_DECLARE\(apr_status_t\)\s+apr_shm_remove/;
my $end_apr_shm_remove = qr/^\}/;

sub read_apr_shm_remove {
    my $file = shift;
    my ($in_func, @func_lines);

    open my $fh, "<", $file;
    $in_func = 0;
    while(<$fh>) {
        if($in_func || !$in_func && /$start_apr_shm_remove/) {
            $in_func = 1;
            push @func_lines, $_;
        }
        if($in_func && /$end_apr_shm_remove/) {
            last;
        }
    }
    return @func_lines;
}

my ($fh, @missing_func_lines, @lines);

@missing_func_lines = read_apr_shm_remove($shm_c)
    or die "apr_shm_remove is not found in $shm_c.";

open $fh, "<", $mod_dosdetector_c;
while(<$fh>) {
    push @lines, $_;
    if(/code for apache 2\.0/) {
        push @lines, qq(#include "apache20.h"\n);
        @lines = (@lines, @missing_func_lines);
    }
}
close $fh;

open $fh, ">", $mod_dosdetector_c;
print $fh @lines;
close $fh;

