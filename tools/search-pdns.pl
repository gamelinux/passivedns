#!/usr/bin/perl

# ----------------------------------------------------------------------
# Search in PassiveDNS DB
# Copyright (C) 2011-2012, Edward Fjellskål <edwardfjellskaal@gmail.com>
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

use strict;
use warnings;
use POSIX ('strftime');
use Time::Local;
use Date::Simple ('date', 'today');
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;

# You need to set DB user,password and host to connect to...
my $db_host      = 'localhost';
my $DB           = 'pdns';
my $db_user_name = 'pdns';
my $db_password  = 'pdns';
my $DLIMIT       =    100;

=head1 NAME

    search-pdns.pl  -  Search in the PassiveDNS database

=head1 VERSION

    0.1.0

=head1 SYNOPSIS

$ search-pdns.pl [options]

  OPTIONS:

    -s            : %IP/Domain%
    -r            : Enables raw search
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

GetOptions(
    'd=s'           => \$DEBUG,
    's=s'           => \$SEARCH,
    'r'             => \$RAW,
    'first-seen=s'  => \$FROM_DATE,
    'last-seen=s'   => \$TO_DATE,
    'limit=s'       => \$LIMIT,
);

if ($SEARCH eq "") {
   print "[*] You need to search for something....\n";
   exit 0;
}

my $dsn = "DBI:mysql:$DB:" . $db_host;
my $dbh = DBI->connect($dsn, $db_user_name, $db_password);

our ($QUERY, $QUERY1, $QUERY2) = q();

$QUERY = qq[SELECT query, answer, first_seen, last_seen, ttl, maptype FROM pdns WHERE ];

if (defined $FROM_DATE ) {
    if ($FROM_DATE=~ /^\d\d\d\d\-\d\d\-\d\d$/) {
       print "Searching from date: $FROM_DATE 00:00:01\n" if $DEBUG;
       $QUERY1 = $QUERY . qq[first_seen > '$FROM_DATE 00:00:01' ];
    } elsif ($FROM_DATE=~ /^\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d$/) {
       print "Searching from date: $FROM_DATE\n" if $DEBUG;
       $QUERY1 = $QUERY . qq[first_seen > '$FROM_DATE' ];
    }
} else {
    print "Searching from date: Thu Jan  1 00:00:00 UTC 1970\n" if $DEBUG;
    $QUERY1 = $QUERY . qq[first_seen > '1970-01-01 00:00:01' ];
}

if (defined $TO_DATE) {
    if ($TO_DATE =~ /^\d\d\d\d\-\d\d\-\d\d$/) {
       print "Searching to date: $TO_DATE 23:59:59\n" if $DEBUG;
       $QUERY1 = $QUERY1 . qq[AND last_seen < '$TO_DATE' ];
    } elsif ($TO_DATE =~ /^\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d$/) {
       print "Searching to date: $TO_DATE\n" if $DEBUG;
       $QUERY1 = $QUERY1 . qq[AND last_seen < '$TO_DATE' ];
    }
}

$QUERY2 = $QUERY1;

if (defined $SEARCH) {
    print "Searching for: $SEARCH\n" if $DEBUG;
    if ( $RAW == 1 ) {
       $QUERY1 = $QUERY1 . qq[AND query  like '$SEARCH' ];
       $QUERY2 = $QUERY2 . qq[AND answer like '$SEARCH' ];
    } else {
       $QUERY1 = $QUERY1 . qq[AND query  like '%$SEARCH%' ];
       $QUERY2 = $QUERY2 . qq[AND answer like '%$SEARCH%' ];
    }
}

$QUERY = $QUERY1 . qq[ UNION ] . $QUERY2;

if (defined $LIMIT && $LIMIT =~ /^([\d])+$/) {
    print "Limit: $LIMIT\n" if $DEBUG;
    $DLIMIT = $LIMIT;
    $QUERY = $QUERY . qq[ORDER BY last_seen LIMIT $LIMIT ];
} else {
    print "Limit: $DLIMIT\n" if $DEBUG;
    $QUERY = $QUERY . qq[ORDER BY last_seen LIMIT $DLIMIT ];
}

print "\nmysql> $QUERY;\n\n" if $DEBUG;

exit 0 if $DEBUG > 1;

my $pri = $dbh->prepare( qq{ $QUERY } );
$pri->execute();

my $cnt = 0;
print "                                            === PassiveDNS ===\n\n";
print "       FirstSeen     |       LastSeen       |  TYPE |  TTL   |               Query                |  Answer\n";
print "---------------------------------------------------------------------------------------------------------------------\n";
while (my ($query, $answer, $firstseen, $lastseen, $ttl, $maptype) = $pri->fetchrow_array()) {
# 2010-10-07 11:33:40 2011-03-08 15:25:04 60.10.4.94      A      N/A   exchange.dynamicdns.co.uk
    next if not defined $query or not defined $answer;
    $cnt++;
    #my $FS = strftime "%Y-%m-%d %H:%M:%S", localtime($firstseen);
    #my $LS = strftime "%Y-%m-%d %H:%M:%S", localtime($lastseen);
    printf("%20s | %20s | %5s | %6s | %-34s | %12s\n", $firstseen, $lastseen, $maptype, $ttl, $query, $answer);
}
print "Displayed $cnt (sql limit: $DLIMIT)\n";

$pri->finish();
$dbh->disconnect();

=head1 AUTHOR

    Edward Fjellskaal <edwardfjellskaal@gmail.com>

=head1 COPYRIGHT

    Copyright (C) 2011, Edward Fjellskaal (edwardfjellskaal@gmail.com)

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
