#!/usr/bin/perl

# ----------------------------------------------------------------------
# Search in PassiveDNS DB
# Copyright (C) 2011-2026, Edward Fjellskål <edwardfjellskaal@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# ----------------------------------------------------------------------
# Added Resource Record Type :  hookol 20180321

use strict;
use warnings;
use POSIX ('strftime');
use Time::Local;
use Date::Simple ('date', 'today');
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;

# Password comes from the environment. Host, user, and database name
# fall back to localhost / pdns / pdns.
my $db_host      = $ENV{PDNS_DB_HOST} // 'localhost';
my $DB           = $ENV{PDNS_DB_NAME} // 'pdns';
my $db_user_name = $ENV{PDNS_DB_USER} // 'pdns';
my $db_password  = $ENV{PDNS_DB_PASSWORD};
my $DLIMIT       =    100;

=head1 NAME

    search-pdns.pl  -  Search in the PassiveDNS database

=head1 VERSION

    0.1.1

=head1 SYNOPSIS

$ search-pdns.pl [options]

  OPTIONS:

    -s            : %IP/Domain%
    -r            : Enables raw search
    -t            : Resource Record Type (A, NS, MX, SOA, etc.)
    --first-seen  : Date to search from in iso format (2010-01-01 etc.)
    --last-seen   : Date to search to in iso format (2020-01-01 etc.)
    --limit       : Limit on search results (100)

  EXAMPLES:

    # Searches for "%facebook%"
    search-pdns.pl -s "facebook"

    # Searches for "^facebook.%.com$"
    search-pdns.pl -r -s "facebook.%.com"

    # Searches for domains/IPs that existed just one day, 2011-01-01.
    search-pdns.pl --first-seen 2011-01-01 --last-seen 2011-01-01 

=cut

our $DEBUG         = 0; # Set to 1 for debugging, 2 to exit before the sql call
our $RAW           = 0;
our $SEARCH        = "%";
our $FROM_DATE;
our $TO_DATE;
our $LIMIT;
our $TYPE;

GetOptions(
    'd=s'           => \$DEBUG,
    's=s'           => \$SEARCH,
    'r'             => \$RAW,
    'first-seen=s'  => \$FROM_DATE,
    'last-seen=s'   => \$TO_DATE,
    'limit=s'       => \$LIMIT,
    't=s'           => \$TYPE,
);

if ($SEARCH eq "") {
   print "[*] You need to search for something....\n";
   exit 0;
}

die "PDNS_DB_NAME must be an identifier\n" unless $DB =~ /^[A-Za-z0-9_]+$/;
die "Set PDNS_DB_PASSWORD\n" unless defined $db_password && $db_password ne '';

my $from = '1970-01-01 00:00:01';
if (defined $FROM_DATE) {
    if ($FROM_DATE =~ /^\d\d\d\d\-\d\d\-\d\d$/) {
        $from = "$FROM_DATE 00:00:01";
    } elsif ($FROM_DATE =~ /^\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d$/) {
        $from = $FROM_DATE;
    } else {
        die "first-seen must be YYYY-MM-DD or YYYY-MM-DD HH:MM:SS\n";
    }
    print "Searching from date: $from\n" if $DEBUG;
}

my $to;
if (defined $TO_DATE) {
    if ($TO_DATE =~ /^\d\d\d\d\-\d\d\-\d\d$/) {
        $to = "$TO_DATE 23:59:59";
    } elsif ($TO_DATE =~ /^\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d$/) {
        $to = $TO_DATE;
    } else {
        die "last-seen must be YYYY-MM-DD or YYYY-MM-DD HH:MM:SS\n";
    }
    print "Searching to date: $to\n" if $DEBUG;
}

if (defined $LIMIT) {
    die "limit must be a number\n" unless $LIMIT =~ /^\d+$/;
    $DLIMIT = $LIMIT + 0;
    $DLIMIT = 1 if $DLIMIT < 1;
    $DLIMIT = 10000 if $DLIMIT > 10000;
}
print "Limit: $DLIMIT\n" if $DEBUG;

if (defined $TYPE && $TYPE ne '') {
    die "RR type must be alphanumeric\n" unless $TYPE =~ /^[A-Za-z0-9]{1,10}$/;
}

sub like_escape {
    my ($s) = @_;
    $s =~ s/([\\%_])/\\$1/g;
    return $s;
}

my $like = $RAW ? $SEARCH : '%' . like_escape($SEARCH) . '%';
print "Searching for: $SEARCH\n" if $DEBUG;

my @bind = ($from);
my $where = 'first_seen > ?';
if (defined $to) {
    $where .= ' AND last_seen < ?';
    push @bind, $to;
}
if (defined $TYPE && $TYPE ne '') {
    $where .= ' AND maptype = ?';
    push @bind, $TYPE;
}

my $QUERY = qq[SELECT query, answer, first_seen, last_seen, ttl, count, maptype FROM $DB.pdns WHERE $where AND query LIKE ?
 UNION
 SELECT query, answer, first_seen, last_seen, ttl, count, maptype FROM $DB.pdns WHERE $where AND answer LIKE ?
 ORDER BY last_seen LIMIT $DLIMIT];

print "\nmysql> $QUERY;\n\n" if $DEBUG;

exit 0 if $DEBUG > 1;

my $dsn = "DBI:mysql:database=$DB;host=$db_host";
my $dbh = DBI->connect($dsn, $db_user_name, $db_password, {RaiseError => 1, PrintError => 0})
    or die "database connect failed: $DBI::errstr\n";

my $pri = $dbh->prepare($QUERY);
$pri->execute(@bind, $like, @bind, $like);

my $cnt = 0;
print "                                            === PassiveDNS ===\n\n";
print "       FirstSeen     |       LastSeen      |  TYPE |  TTL   |               Query                |  Answer |  Count\n";
print "------------------------------------------------------------------------------------------------------------------------------\n";
while (my ($query, $answer, $firstseen, $lastseen, $ttl, $count, $maptype) = $pri->fetchrow_array()) {
    next if not defined $query or not defined $answer;
    $cnt++;
    #printf("%20s | %20s | %5s | %6s | %-34s | %12s\n", $firstseen, $lastseen, $maptype, $ttl, $query, $answer);
    printf("%20s | %19s | %5s | %6s | %-34s | %14s | %8s\n", $firstseen, $lastseen, $maptype, $ttl, $query, $answer, $count);

}
print "Displayed $cnt (sql limit: $DLIMIT)\n";

$pri->finish();
$dbh->disconnect();

=head1 AUTHOR

    Edward Fjellskaal <edwardfjellskaal@gmail.com>

=head1 COPYRIGHT

    Copyright (C) 2011-2026, Edward Fjellskaal (edwardfjellskaal@gmail.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=cut
