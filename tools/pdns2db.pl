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
use POSIX qw(setsid strftime);
use DateTime;
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;

#use Data::Dumper;

=head1 NAME

 pdns2db.pl - Load passive DNS data from passivedns into a DB

=head1 VERSION

0.3

=head1 SYNOPSIS

 $ pdns2db.pl [options]

 OPTIONS:

 --file <file>          : set the file to monitor for passivedns entries (/var/log/passivedns.log)
 --batch                : process a file and exit when done
 --skiplist <file>      : file with a list of domains to skip DB insertion
 --onlylist <file>      : file with a list of domains to only insert into DB
 --whitelist <file>     : file with a list of domains to not check for in blacklist
 --blacklist <file>     : file with a list of domains to alert on
 --skiplist-pcre <file> : file with regexp list of domains to skip DB insertion
 --onlylist-pcre <file> : file with regexp list of domains to only insert into DB
 --whitelist-pcre <file>: file with regexp list of domains to not check for in blacklist
 --blacklist-pcre <file>: file with regexp list of domains to alert on
 --alertlog <file>      : file to log alerts to (/var/log/passivedns-alert.log)
 --nodb                 : dont talk to the DB at all
 --daemon               : enables daemon mode
 --verbose              : enables some verboseness
 --debug <int>          : enable debug messages (default: 0 (disabled))
 --help                 : this help message
 --version              : show pdns2db.pl version

=cut

our $VERSION       = 0.3;
our $DEBUG         = 0;
our $VERBOSE       = 0;
our $DAEMON        = 0;
our $TIMEOUT       = 1;
my  $PDNSFILE      = q(/var/log/passivedns.log);
my  $LOGFILE       = q(/var/log/passivedns-run.log);
my  $ALERTLOG      = q(/var/log/passivedns-alert.log);
my  $PIDFILE       = q(/var/run/pdns2db.pid);
our $DB_NAME       = "pdns";
our $DB_HOST       = "127.0.0.1";
our $DB_PORT       = "3306";
our $DB_USERNAME   = "pdns";
our $DB_PASSWORD   = "pdns";
our $DBI           = "DBI:mysql:$DB_NAME:$DB_HOST:$DB_PORT";
our $TABLE_NAME    = "pdns";
our $AUTOCOMMIT    = 0;
our $BATCH         = 0;
our $dbh;
our $NODB          = 0;
my $DOMAIN_BLACKLIST_FILE       = undef;
my $DOMAIN_BLACKLIST_FILE_PCRE  = undef;
my $DOMAIN_WHITELIST_FILE       = undef;
my $DOMAIN_WHITELIST_FILE_PCRE  = undef;
my $DOMAIN_DBSKIPLIST_FILE      = undef;
my $DOMAIN_DBSKIPLIST_FILE_PCRE = undef;
my $DOMAIN_DBONLYLIST_FILE      = undef;
my $DOMAIN_DBONLYLIST_FILE_PCRE = undef;

GetOptions(
   'file=s'           => \$PDNSFILE,
   'skiplist=s'       => \$DOMAIN_DBSKIPLIST_FILE,
   'skiplist-pcre=s'  => \$DOMAIN_DBSKIPLIST_FILE_PCRE,
   'whitelist=s'      => \$DOMAIN_WHITELIST_FILE,
   'whitelist-pcre=s' => \$DOMAIN_WHITELIST_FILE_PCRE,
   'blacklist=s'      => \$DOMAIN_BLACKLIST_FILE,
   'blacklist-pcre=s' => \$DOMAIN_BLACKLIST_FILE_PCRE,
   'onlylist=s'       => \$DOMAIN_DBONLYLIST_FILE,
   'onlylist-pcre=s'  => \$DOMAIN_DBONLYLIST_FILE_PCRE,
   'alertlog=s'       => \$ALERTLOG,
   'batch'            => \$BATCH,
   'nodb'             => \$NODB,
   'debug=s'          => \$DEBUG,
   'daemon'           => \$DAEMON,
   'verbose'          => \$VERBOSE,
);

our $HASH_BLACKLIST = {};
our $HASH_WHITELIST = {};
our $HASH_DBSKIPLIST= {};
our $HASH_DBONLYLIST= {};
$HASH_BLACKLIST->{'pcre'}    = [load_domain_list_pcre($DOMAIN_BLACKLIST_FILE_PCRE)]  if $DOMAIN_BLACKLIST_FILE_PCRE;
$HASH_BLACKLIST->{'static'}  = load_domain_list_static($DOMAIN_BLACKLIST_FILE)       if $DOMAIN_BLACKLIST_FILE;
$HASH_WHITELIST->{'pcre'}    = [load_domain_list_pcre($DOMAIN_WHITELIST_FILE_PCRE)]  if $DOMAIN_WHITELIST_FILE_PCRE;
$HASH_WHITELIST->{'static'}  = load_domain_list_static($DOMAIN_WHITELIST_FILE)       if $DOMAIN_WHITELIST_FILE;
$HASH_DBSKIPLIST->{'pcre'}   = [load_domain_list_pcre($DOMAIN_DBSKIPLIST_FILE_PCRE)] if $DOMAIN_DBSKIPLIST_FILE_PCRE;
$HASH_DBSKIPLIST->{'static'} = load_domain_list_static($DOMAIN_DBSKIPLIST_FILE)      if $DOMAIN_DBSKIPLIST_FILE;
$HASH_DBONLYLIST->{'pcre'}   = [load_domain_list_pcre($DOMAIN_DBONLYLIST_FILE_PCRE)] if $DOMAIN_DBONLYLIST_FILE_PCRE;
$HASH_DBONLYLIST->{'static'} = load_domain_list_static($DOMAIN_DBONLYLIST_FILE)      if $DOMAIN_DBONLYLIST_FILE;

if (($HASH_WHITELIST) && (not $HASH_BLACKLIST)){
    logger("[W] Whitelist without Blacklist does not make sense!");
    $HASH_WHITELIST = undef; 
}

if ((not defined $HASH_DBONLYLIST->{'static'}) && (not defined $HASH_DBONLYLIST->{'pcre'})) {
    # Should also check that there are any entries if they are defined.
    $HASH_DBONLYLIST = undef;
}

# Signal handlers
use vars qw(%sources);
#$SIG{"HUP"}   = \&recreate_merge_table;
$SIG{"INT"}   = sub { game_over() };
$SIG{"TERM"}  = sub { game_over() };
$SIG{"QUIT"}  = sub { game_over() };
$SIG{"KILL"}  = sub { game_over() };
#$SIG{"ALRM"}  = sub { file_watch(); alarm $TIMEOUT; };

logger("[*] Starting pdns2db.pl");

# Prepare to meet the world of Daemons
if ( $DAEMON ) {
   logger("[*] Daemonizing...");
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

if ($NODB == 0) {
    logger("[*] Connecting to database...");
    $dbh = DBI->connect($DBI,$DB_USERNAME,$DB_PASSWORD, {RaiseError => 1, mysql_auto_reconnect=>1}) or die "$DBI::errstr";
    # Setup the pdns table, if not exist
    setup_db();
} else {
    logger("[*] Skipping database operations...");
}

# Start file_watch() which looks for new dns data and puts them into db
logger("[*] Looking for passive DNS data in file: $PDNSFILE");
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

      if (!defined $startsize) {
         # No such file (Log rotate?)
         sleep $TIMEOUT;
         next;
      }

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

      if ($BATCH == 1) {
         logger("[*] Processing of $logfile is done, exiting!");
         exit 0;
      }
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
       my $wret = 0;
       my $bret = 0;
       my $sret = 0;

       my @elements = split(/\|\|/,$line);
       unless(@elements == 9) {
            logger("[W] Not valid Nr. of args in format: '$fname'");
            next LINE;
       }

       my ($tst, $cip, $sip, $rr, $query, $type, $answer, $ttl, $count) = @elements;
       $query  =~ s/^(.*)\.$/$1/;
       $answer =~ s/^(.*)\.$/$1/;

       if (($HASH_DBSKIPLIST) && ($sret = match_domain($query, $answer, $HASH_DBSKIPLIST))) {
           logger("[*] Domain marked to skip DB insertion: $query or $answer") if $VERBOSE;
           next LINE;
       }

       if (($HASH_WHITELIST) && ($HASH_BLACKLIST) &&($wret = match_domain($query, $answer, $HASH_WHITELIST))) {
           logger("[*] Whitelisted domain: $query or $answer") if $VERBOSE;
       } elsif (($HASH_BLACKLIST) && ($bret = match_domain($query, $answer, $HASH_BLACKLIST))) {
           logger("[*] Blacklisted domain: $query or $answer") if $VERBOSE;
           if (open (ALOG, ">> $ALERTLOG") ) {
               print ALOG $line, "\n";
               close (ALOG);
           } else {
               logger("[W] Problems with open($ALERTLOG): $!");
           }
       }

       if (($HASH_DBONLYLIST) && ($sret = match_domain($query, $answer, $HASH_DBONLYLIST))) {
           logger("[*] Onlylisted domain: $query or $answer") if $VERBOSE;
           put_dns_to_db(@elements) if $NODB == 0;
       } elsif (not defined $HASH_DBONLYLIST) {
           put_dns_to_db(@elements) if $NODB == 0;
       } else {
           put_dns_to_db(@elements) if $NODB == 0;
       }
    }
    close(LOGFILE);
}

sub put_dns_to_db {
    # 1322849924.123456||192.168.1.1||8.8.8.8||IN||www.adobe.com.||CNAME||www.wip4.adobe.com.||3600||22
    # 1322849924.123456||192.168.1.1||8.8.8.8||IN||www.adobe.com.||A||193.104.215.61||600||11
    my ($tst, $cip, $sip, $rr, $query, $type, $answer, $ttl, $count) = @_;
    my ($ts, $tsu) = split(/\./,$tst);
    my $tsl = $ts;

    $query  =~ s/^(.*)\.$/$1/; # Strip trailing dot
    $answer =~ s/^(.*)\.$/$1/; # Strip trailing dot
    $query  =~ s/(')/\\$1/g; # Wash "user-input" for non-friendly sql chars
    $answer =~ s/(')/\\$1/g; # Wash "user-input" for non-friendly sql chars

    my ($sql, $sth);

    eval{
      $sql = qq[
             INSERT INTO $TABLE_NAME (
               QUERY,RR,MAPTYPE,ANSWER,TTL,COUNT,LAST_SEEN,FIRST_SEEN
             ) VALUES (
               '$query','$rr','$type','$answer','$ttl','$count',FROM_UNIXTIME($ts),FROM_UNIXTIME($tsl)
             ) ON DUPLICATE KEY UPDATE
               TTL = if (TTL < $ttl, $ttl, TTL),
               COUNT = COUNT + '$count',
               LAST_SEEN = if (LAST_SEEN < FROM_UNIXTIME($ts), FROM_UNIXTIME($ts), LAST_SEEN),
               FIRST_SEEN = if (FIRST_SEEN > FROM_UNIXTIME($ts), FROM_UNIXTIME($ts), FIRST_SEEN)
             ];
      logger("[D] $sql") if $DEBUG > 1;
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
   logger("[*] Creating $TABLE_NAME...");
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
        COUNT         BIGINT(20) UNSIGNED  NOT NULL DEFAULT  '1',   \
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
       logger("[D] Table $tablename does not exist.") if $DEBUG;
       return 0;
    }
    else{
       return 1;
    }
}

=head2 load_domain_list

 Loads domains from file

 File format:
 <domain written in regexp>

 Example:
  ^news\..*daily\.com$

=cut

sub load_domain_list_pcre {
    my $file = shift;
    my %signatures;
    my $cnt = 0;

    open(my $FH, "<", $file) or die "[E] Could not open '$file': $!";

    LINE:
    while (my $line = readline $FH) {
        chomp $line;
        $line =~ s/\#.*//;
        $line =~ s/\t//g;
        $line =~ s/ //g;
        next LINE unless($line); # empty line
        # One should check for a more or less sane signature file.

        logger("[D] $line") if $DEBUG;
        $signatures{$line} = [qr{$line}];
        $cnt++;
    }
    logger("[D] Loaded $cnt domains") if $DEBUG;

    return map { $signatures{$_} }
            sort { length $b <=> length $a }
             keys %signatures;
}

sub load_domain_list_static {
    my $file = shift;
    my $signatures = {};
    my $cnt = 0;

    open(my $FH, "<", $file) or die "[E] Could not open '$file': $!";

    LINE:
    while (my $line = readline $FH) {
        chomp $line;
        $line =~ s/\#.*//;
        $line =~ s/\t//g;
        $line =~ s/ //g;
        next LINE unless($line); # empty line
        # One should check for a more or less sane signature file.

        logger("[D] $line") if $DEBUG;
        $signatures->{"$line"} = 1;
        $cnt++;
    }
    logger("[D] Loaded $cnt static domains") if $DEBUG;

    return $signatures;
}

=head2 match_domain

 Takes input: $domain, $@domain_list_to_match_on
 Returns 1 if found, 0 if not.

=cut

sub match_domain {
    my ($query, $answer, $MHASH) = @_;

    # First we should match agains "static" domain list.
    if ($MHASH->{'static'}->{"$query"}) {
        logger("[D] Domain $query match on static query domain: $query") if $DEBUG;
        return 1;
    } elsif ($MHASH->{'static'}->{"$answer"}) {
        logger("[D] Domain $answer match on static answer domain: $answer") if $DEBUG;
        return 1;
    } else {
        logger("[D] No static match on domain: $query or $answer") if $DEBUG;
    }

    # Check domain against domains in expensive pcre list
    my $CRAP = $MHASH->{'pcre'};
    for my $s (@$CRAP) {
        my $re = $s->[0];
        if ($query =~ /$re/) {
            logger("[D] Domain $query match on pcre: $re") if $DEBUG;
            return 1;
        } elsif ($answer =~ /$re/) {
            logger("[D] Domain $answer match on pcre: $re") if $DEBUG;
            return 1;
        }
    }

    logger("[D] No pcre match on domain: $query or $answer") if $DEBUG;
    return 0;
}

=head2 logger

 Adds time prefix to logg output. Takes $msg as input.

=cut

sub logger {
    my $msg = shift;
    print strftime('%F %H:%M:%S', localtime), " $msg\n";
}
=head2 game_over

 Terminates the program in a sainfull way.

=cut

sub game_over {
    logger("[*] Terminating...");
    if (defined $dbh) {
        $dbh->disconnect;
    }
    unlink ($PIDFILE);
    exit 0;
}

=head1 AUTHOR

 Edward Fjellskaal <edwardfjellskaal@gmail.com>

=head1 COPYRIGHT

 This library is free software, you can redistribute it and/or modify
 it under the same terms as Perl itself.

=cut
