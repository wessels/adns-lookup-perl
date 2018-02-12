#!/usr/bin/perl
use strict;
use warnings;
use Net::DNS;
use Time::HiRes;

my $res = new Net::DNS::Resolver;
my $TIMEOUT = 30;
my $outstanding;
my $noutstanding = 0;

sub dns_send {
	my $name = shift;
	my $type = shift;
	my $sock = $res->bgsend($name, $type);
	my $t0 = Time::HiRes::time;
	$outstanding->{$t0}->{sock} = $sock;
	$outstanding->{$t0}->{res} = $res;
	$outstanding->{$t0}->{qname} = $name;
	$outstanding->{$t0}->{qtype} = $type;
	$noutstanding++;
}

sub dns_recv {
	my $pkt = shift;
	my $res = shift;
	my $t = shift;
	my $name = shift;
	my $type = shift;
	if ('NOERROR' ne $pkt->header->rcode) {
		foreach my $q ($pkt->question) {
			print join(' ', $q->name, $q->type, $pkt->header->rcode). "\n";
			last;
		}
		return;
	} 
	foreach my $rr ($pkt->answer) {
		next unless $rr->type eq $type;
		print join(' ', $rr->name, $rr->type, $pkt->header->rcode, $rr->rdstring). "\n";
	}
}


sub collect() {
	my $now = Time::HiRes::time;
	foreach my $k (keys %$outstanding) {
		my $res = $outstanding->{$k}->{res};
		my $sock = $outstanding->{$k}->{sock};
		my $qn = $outstanding->{$k}->{qname};
		my $qt = $outstanding->{$k}->{qtype};
		if ($res->bgisready($sock)) {
			#
			# receive response
			#
			my $pkt = $res->bgread($sock);
			$sock->close;
			$noutstanding--;
			delete $outstanding->{$k};
			if (!$pkt) {
				warn "$qn $qt: ". $res->errorstring. ", re-queueing\n";
				dns_send($qn, $qt);
				next;
			}
			if ($pkt->header->tc) {
				print "$qn $qt TRUNCATED\n";
				next;
			}
			dns_recv($pkt, $res, $k, $qn, $qt);
		} elsif ($now > $k + $TIMEOUT) {
			#
			# timeout
			#
			$sock->close;
			$noutstanding--;
			delete $outstanding->{$k};
			warn "Timeout for $qn $qt, re-queueing\n";
			dns_send($qn, $qt);
		}
	}
}

while (<>) {
	chomp;
	my ($name,$type) = split;
	my $q = new Net::DNS::Question($name, $type);
	dns_send($q->qname, $q->qtype);
	do { collect(); } while $noutstanding > 50;
}

while ($noutstanding > 0) {
	collect();
	Time::HiRes::usleep(100000);
}
