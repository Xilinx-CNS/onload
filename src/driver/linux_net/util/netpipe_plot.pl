#!/usr/bin/perl -w

use strict;
use warnings;

my $throughput_template = {
  name => "throughput",
  title => "Ethernet Throughput",
  xlabel => "Transfer block size (bytes)",
  ylabel => "Throughput (Mbps)",
  logscale => { x => 1 },
  columns => "1:2",
};

my $signature_template = {
  name => "signature",
  title => "Ethernet Signature Graph",
  xlabel => "Time (seconds)",
  ylabel => "Throughput (Mbps)",
  logscale => { x => 1 },
  columns => "3:2",
};

my $saturation_template = {
  name => "saturation",
  title => "Ethernet Saturation Graph",
  xlabel => "Time (seconds)",
  ylabel => "Transfer block size (bytes)",
  logscale => { x => 1, y => 1 },
  columns => "3:1",
};

sub plot {
  my $template = shift;
  my $datasets = shift;

  my $filename = ".".$template->{name}.".plot";
  open my $fh, ">$filename" or die "Could not create $filename: $!\n";
  print $fh "set title \"$template->{title}\"\n";
  print $fh "set xlabel \"$template->{xlabel}\"\n";
  print $fh "set ylabel \"$template->{ylabel}\"\n";
  print $fh "set logscale x\n" if $template->{logscale}->{x};
  print $fh "set logscale y\n" if $template->{logscale}->{y};
  my @plots = map { "\"$_\" using $template->{columns} ".
			"title \"$_\" with lines" } @$datasets;
  print $fh "plot ".join ( ", ", @plots )."\n";
  close $fh;
  system ( "/usr/bin/gnuplot", "-persist", $filename );
}

die "Syntax: $0 dataset1 [ dataset2 ... ]\n" unless @ARGV;
my $datasets = [ @ARGV ];

plot ( $throughput_template, $datasets );
plot ( $signature_template, $datasets );
plot ( $saturation_template, $datasets );
