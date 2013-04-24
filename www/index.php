<?php
# --------------------------------------------------------------------------
# Copyright (C) 2013 Edward Fjellskål <edward.fjellskaal@gmail.com>
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
# --------------------------------------------------------------------------
#
# Configure Start
$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";
$DBLIMIT  = 500;
# Configure End

$query = sanitize("query"); if (empty($query)) $query = "";

print_header();
print_search_body();

if ($query) {
  echo "<center>";
  mysql_connect($DATABASE, $DBUSER, $DBPASSWD) or die(mysql_error());
  mysql_select_db($DBTABLE) or die(mysql_error());
  if ( filter_var($query, FILTER_VALIDATE_IP) ) {
    echo "<b>PassiveDNS Records for IP: ". $query ."</b><br><br>";
    $domains = mysql_query("SELECT * FROM pdns WHERE answer='$query' LIMIT $DBLIMIT");
    if(mysql_num_rows($domains)==0){
      echo "<b>No records found...</b><br><br>";
    } else {
      echo "<table cellpadding='2'><tr><td><b>First Seen</b></td><td><b>Last Seen</b></td><td><b>Type</b></td><td><b>TTL</b></td><td><b>Query</b></td><td><b>Answer</b></td><td><b>Count</b></td></tr>";
      echo '
           ';
      while ( $r = mysql_fetch_array($domains) ) {
        echo "<tr>";
        echo "<td>". $r['FIRST_SEEN'] ."</td>";
        echo "<td>". $r['LAST_SEEN'] ."</td>";
        echo "<td>". $r['MAPTYPE'] ."</td>";
        echo "<td>". $r['TTL'] ."</td>";
        echo "<td><a href='?query=". $r['QUERY']  ."'>". $r['QUERY']  ."</a></td>";
        echo "<td><a href='?query=". $r['ANSWER'] ."'>". $r['ANSWER'] ."</a></td>";
        echo "<td>". $r['COUNT'] ."</td>";
        echo "</tr>";
      }
    }
  } else {
    echo "<b>PassiveDNS Records for Domain: ". $query ."</b> <br><br>";
    $domains = mysql_query("SELECT * FROM pdns WHERE query='$query' OR query LIKE '%.$query' LIMIT $DBLIMIT");
    if(mysql_num_rows($domains)==0){
      echo "<b>No records found...</b><br><br>";
    } else {
      echo "<table cellpadding='2'><tr><td><b>First Seen</b></td><td><b>Last Seen</b></td><td><b>Type</b></td><td><b>TTL</b></td><td><b>Query</b></td><td><b>Answer</b></td><td><b>Count</b></td></tr>";
      echo '
           ';
      while ( $r = mysql_fetch_array($domains) ) {
        echo "<tr>";
        echo "<td>". $r['FIRST_SEEN'] ."</td>";
        echo "<td>". $r['LAST_SEEN'] ."</td>";
        echo "<td>". $r['MAPTYPE'] ."</td>";
        echo "<td>". $r['TTL'] ."</td>";
        echo "<td><a href='?query=". $r['QUERY']  ."'>". $r['QUERY']  ."</a></td>";
        echo "<td><a href='?query=". $r['ANSWER'] ."'>". $r['ANSWER'] ."</a></td>";
        echo "<td>". $r['COUNT'] ."</td>";
        echo "</tr>";
      }
    }
  }
  echo "</center>";
}

print_tail();

function getVar($in) {

    if (isset($_POST[$in])) {
        $out = $_POST[$in];
    } else {
        $out = $_GET[$in];
    }

    if (get_magic_quotes_gpc()) {
        if (is_array($out)) {
            foreach ($out as $el) {
                $array[] = stripslashes($el);
            }
            $out = $array;
        } else {
            $out = stripslashes($out);
        }
    }

    return $out;
}

function sanitize($in) {
  $qvar =  strip_tags(addslashes(getVar($in)));
  
  if ( preg_match('/(\w+\.)*\w{2,}\.\w{2,4}$/i', $qvar) ) {
    /* Might be a domain */
    return $qvar;
  } else if ( preg_match('/^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])$/', $qvar) ) {
    /* Might be a IPv4 */
    return $qvar;
  } else if (preg_match('/^[a-f0-9]{1,4}:([a-f0-9]{0,4}:){1,6}[a-f0-9]{1,4}$/i', $qvar)) {
    /* FE80:0000:0000:0000:0202:B3FF:FE1E:8329 or FE80::0202:B3FF:FE1E:8329 */
    /* or even 2001:db8::1 or 0:0:0:0:0:ffff:192.1.56.10  */
    /* Might be a IPv6 */
    return $qvar;
  } else {
    /* B0rked */
    echo "B0rked";
    return "";
  }
}

function print_header() {
  echo "<html>
<head>
<title>PassiveDNS</title>";
  echo '
<style type="text/css">
  td,p,div.box {
          color: #000;
          margin: 4px;
          padding: 4px;
          font-family: verdana, arial, helvetica, sans-serif;
          font-size: 13px;
          font-weight: normal;
          border-bottom: 1px none #BFE9FF;
  }
  tr.odd {
          background-color: #E2F1FF;
  }
  table
  { 
  margin-left: auto;
  margin-right: auto;
  }
  </style>
  </head>
  <body><center>
  <div style="width: 860px; margin:auto;">
  <p>
   This data has been collected using <a href="http://github.com/gamelinux/passivedns">PassiveDNS</a>.
  </p>
  </div>
  <table width="860" cellpadding="2" cellspacing="0">
';
}

function print_search_body() {
  echo '<tr><td><center><form name search method="GET">';
  echo 'Domain/IP: <input type="text" maxlength="300" name="query">';
  echo '<input type="submit" value="Search"></form><center><br>
';
}

function print_tail() {
  echo '
</center>
</body>
</html>';
}

?>
