#!/usr/bin/perl

# ----------------------------------------------------------------------
# PassiveDNS to DB
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
use POSIX qw(setsid);
use DateTime;
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;

=head1 NAME

 pdns2db.pl - Load passive DNS data from passivedns into a DB

=head1 VERSION

0.1

=head1 SYNOPSIS

 $ pdns2db.pl [options]

 OPTIONS:

 --file         : set the file to monitor for passivedns entries
 --daemon       : enables daemon mode
 --debug        : enable debug messages (default: 0 (disabled))
 --help         : this help message
 --version      : show pdns2db.pl version

=cut

our $VERSION       = 0.1;
our $DEBUG         = 0;
our $DAEMON        = 0;
our $TIMEOUT       = 1;
my  $PDNSFILE      = "/var/log/passivedns.log";
my  $LOGFILE       = q(/var/log/passivedns-run.log);
my  $PIDFILE       = q(/var/run/pdns2db.pid);
our $DB_NAME       = "pdns";
our $DB_HOST       = "127.0.0.1";
our $DB_PORT       = "3306";
our $DB_USERNAME   = "pdns";
our $DB_PASSWORD   = "pdns";
our $DBI           = "DBI:mysql:$DB_NAME:$DB_HOST:$DB_PORT";
our $TABLE_NAME    = "pdns";
our $AUTOCOMMIT    = 0;

GetOptions(
   'file=s'         => \$PDNSFILE,
   'debug=s'        => \$DEBUG,
   'daemon'         => \$DAEMON,
);

# Signal handlers
use vars qw(%sources);
#$SIG{"HUP"}   = \&recreate_merge_table;
$SIG{"INT"}   = sub { game_over() };
$SIG{"TERM"}  = sub { game_over() };
$SIG{"QUIT"}  = sub { game_over() };
$SIG{"KILL"}  = sub { game_over() };
#$SIG{"ALRM"}  = sub { file_watch(); alarm $TIMEOUT; };

warn "[*] Starting pdns2db.pl\n";

# Prepare to meet the world of Daemons
if ( $DAEMON ) {
   print "[*] Daemonizing...\n";
   chdir ("/") or die "chdir /: $!\n";
   open (STDIN, "/dev/null") or die "open /dev/null: $!\n";
   open (STDOUT, "> $LOGFILE") or die "open > $LOGFILE: $!\n";
   defined (my $dpid = fork) or die "fork: $!\n";
   if ($dpid) {
      # Write PID file
      open (PID, "> $PIDFILE") or die "open($PIDFILE): $!\n";
      print PID $dpid, "\n";
      close (PID);
      exit 0;
   }
   setsid ();
   open (STDERR, ">&STDOUT");
}

warn "[*] Connecting to database...\n";
my $dbh = DBI->connect($DBI,$DB_USERNAME,$DB_PASSWORD, {RaiseError => 1}) or die "$DBI::errstr";
# Setup the pdns table, if not exist
setup_db();

# Start file_watch() which looks for new dns data and puts them into db
warn "[*] Looking for passive DNS data in file: $PDNSFILE\n";
file_watch($PDNSFILE);
exit;

=head1 FUNCTIONS

=head2 setup_db

 Checks if the pdns table exists, if not make it.

=cut

sub setup_db {

   if (checkif_table_exist($TABLE_NAME)) {
      return;
   } else {
      if (new_pdns_table($TABLE_NAME)) {
         die "[E] Table $TABLE_NAME does not exist, and we could not create it! Sorry!\n";
      }
   }
}

=head2 file_watch

 This sub looks for new DNS data in a file.
 Takes $filename to watch as input.

=cut

sub file_watch {
   my $logfile = shift;
   my $startsize = 0;
   my $pos = 0;
   #infinite loop
   while (1) {
      $startsize = (stat $logfile)[7];

      if (!defined $pos) {
         # Initial run.
         $pos = $startsize;
      }

      if ($startsize < $pos) {
         # Log rotated
         #parseLogfile ($rotlogfile, $pos, (stat $rotlogfile)[7]);
         $pos = 0;
      }

      parseLogfile ($logfile, $pos, $startsize);
      $pos = $startsize;

      sleep $TIMEOUT;
   }
}

sub parseLogfile {
    my ($fname, $start, $stop) = @_;
    open (LOGFILE, $fname) or exit 3;
    seek (LOGFILE, $start, 0) or exit 2;

    LINE:
    while (tell (LOGFILE) < $stop) {
       my $line =<LOGFILE>;
       chomp ($line);
       my @elements = split/\|\|/,$line;
       unless(@elements == 7) {
            warn "[*] Error: Not valid Nr. of args in format: '$fname'";
            next LINE;
       }
       put_dns_to_db(@elements);
    }
    close(LOGFILE);
}

sub put_dns_to_db {
    # 1322849924||192.168.1.1||81.167.36.3||IN||www.adobe.com.||CNAME||www.wip4.adobe.com.
    # 1322849924||192.168.1.1||81.167.36.3||IN||www.adobe.com.||A||193.104.215.61
    my ($ts, $cip, $sip, $rr, $query, $type, $answer) = @_;
    my $tsl = $ts;
    my $ttl = 0;    

    $query  =~ s/^(.*)\.$/$1/;
    $answer =~ s/^(.*)\.$/$1/;

    my ($sql, $sth);

    eval{
      $sql = qq[
             INSERT INTO $TABLE_NAME (
               QUERY,RR,MAPTYPE,ANSWER,TTL,LAST_SEEN,FIRST_SEEN
             ) VALUES (
               '$query','$rr','$type','$answer','$ttl',FROM_UNIXTIME($ts),FROM_UNIXTIME($tsl)
             ) ON DUPLICATE KEY UPDATE LAST_SEEN=FROM_UNIXTIME($ts), TTL = '$ttl'
             ];
      warn "$sql\n" if $DEBUG;
      $sth = $dbh->prepare($sql);
      $sth->execute;
      $sth->finish;
   };
   if ($@) {
      # Failed
      return 1;
   }
   return 0;
}

=head2 new_pdns_table

 Creates a new pdns table.
 Takes $tablename as input.

=cut

sub new_pdns_table {
   my ($tablename) = shift;
   my ($sql, $sth);
   warn "[*] Creating $TABLE_NAME...\n";
   eval{
      $sql = "                                                      \
        CREATE TABLE IF NOT EXISTS $tablename                       \
        (                                                           \
        ID            BIGINT(20) UNSIGNED  NOT NULL AUTO_INCREMENT, \
        QUERY         varchar(255)         NOT NULL DEFAULT   '',   \
        MAPTYPE       varchar(10)          NOT NULL DEFAULT   '',   \
        RR            varchar(10)          NOT NULL DEFAULT   '',   \
        ANSWER        varchar(255)         NOT NULL DEFAULT   '',   \
        TTL           int(10)              NOT NULL DEFAULT  '0',   \
        FIRST_SEEN    DATETIME             NOT NULL,                \
        LAST_SEEN     DATETIME             NOT NULL,                \
        PRIMARY KEY (ID),                                           \
        UNIQUE KEY MARQ (MAPTYPE,ANSWER,RR,QUERY),                  \
        KEY query_idx (QUERY),                                      \
        KEY answer_idx (ANSWER)                                     \
        )                                                           \
      ";
      $sth = $dbh->prepare($sql);
      $sth->execute;
      $sth->finish;
   };
   if ($@) {
      # Failed
      return 1;
   }
   return 0;
}


=head2 checkif_table_exist

 Checks if a table exists. Takes $tablename as input and
 returns 1 if $tablename exists, and 0 if not.

=cut

sub checkif_table_exist {
    my $tablename = shift;
    my ($sql, $sth);
    eval {
       $sql = "select count(*) from pdns where 1=0";
       $dbh->do($sql);
    };
    if ($dbh->err) {
       warn "[W] Table $tablename does not exist.\n" if $DEBUG;
       return 0;
    }
    else{
       return 1;
    }
}

=head2 game_over

 Terminates the program in a sainfull way.

=cut

sub game_over {
    warn "[*] Terminating...\n";
    $dbh->disconnect;
    unlink ($PIDFILE);
    exit 0;
}

=head1 AUTHOR

 Edward Fjellskaal <edwardfjellskaal@gmail.com>

=head1 COPYRIGHT

 This library is free software, you can redistribute it and/or modify
 it under the same terms as Perl itself.

=cut
