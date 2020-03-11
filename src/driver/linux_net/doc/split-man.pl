#!/usr/bin/perl

if ($#ARGV < 0) {
   die "where do I put the results?\n";
}

mkdir $ARGV[0],0777;
$state = 0;
while (<STDIN>) {
    if (/^\.TH \"[^\"]*\" 9 \"(?:enum |struct )?([^\"]+)\"/) {
        if ($state == 1) { close OUT }
        $state = 1;
        $fn = "$ARGV[0]/$1.9";
        print STDERR "Creating $fn\n";
        open OUT, ">$fn" or die "can't open $fn: $!\n";
        print OUT $_;
    } elsif ($state != 0) {
        print OUT $_;
    }
}

close OUT;
