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

require "function.php";

# Configure Start
$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";
$DBLIMIT  = 1000;
# Configure End
$o_query = getVar('query');
$query = sanitize("query"); if (empty($query)) $query = "";
$type = getVar("type"); if (empty($type)) $type = "";
if (strtolower($type) == 'basic' || $type == '') {
    $qtype = "and (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    $type = 'basic';
} else if (!in_array(strtolower($type), array('a', 'aaaa', 'ptr', 'cname', 'dname', 'mx', 'naptr', 'ns', 'rp', 'soa', 'srv', 'txt', 'loc', 'rrsig', 'dnskey', 'nsec', 'nsec3', 'ds', 'nsec3param', 'sshfp', 'gpos', 'hinfo'))) {
    $qtype = '';
    $type= 'any';
} else {
    $qtype = "and MAPTYPE = '$type'";
}

$sort = getVar("sort"); if (empty($sort)) $sort = "";
$dir = getVar("dir"); if (empty($dir)) $dir = "desc";
if(!in_array(strtoupper($dir), array('DESC', 'ASC'))) {
    $qdir = $dir = "desc";
} else {
    $qdir = $dir;
    if(!in_array(strtolower($sort), array('first_seen', 'last_seen', 'maptype', 'ttl', 'query', 'answer', 'count', 'asn'))) {
        $qsort = $sort = '';
    } else {
        $qsort = "ORDER BY $sort $qdir";
    }
}

$compare = getVar("compare"); if (empty($compare)) $compare = "";
$ttl = getVar("ttl"); if (!is_numeric($ttl) || $ttl < 0) $ttl = "";
if(!is_numeric($ttl) || $ttl < 0) {
    $qttl = $ttl = '';
} else {
    $qttl = ceil($ttl);
    $qcompare = '';
    if ($compare == 'eq') { $qcompare = '=';$qttl = " AND ttl $qcompare $qttl";}
    elseif ($compare == 'ge') { $qcompare = '>=';$qttl = " AND ttl $qcompare $qttl";}
    elseif ($compare == 'le') { $qcompare = '<=';$qttl = " AND ttl $qcompare $qttl";}
    else { $qttl = $ttl = ''; }  
    if ($qttl != '' && $query == '') $query = '%';
}

print_header();
print_search_body($o_query, $type, $compare, $sort, $dir, $ttl);
$cnt = 0;
if ($query || $qttl != '') {
    echo "<center>";
    $input_arr = array();
    $pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);
    if (filter_var($query, FILTER_VALIDATE_IP) 
            || preg_match('/^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]|\*)\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]|\*)\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]|\*)$/', $query)
            || preg_match('/^[a-f0-9]{1,4}:((\*|([a-f0-9]{0,4}):){1,6}(\*|([a-f0-9]{1,4})))$/i', $query)) {
        $t_query = str_replace('*', '%', $query);
        $input_arr[':query'] = $t_query;
        $sql = "SELECT * FROM pdns WHERE answer LIKE :query $qtype  $qttl $qsort LIMIT $DBLIMIT";
        echo "<b>Passive DNS Records for IP: ". $query ."</b><br><br>";
    } elseif (is_numeric($query)) {
        echo "<b>Passive DNS Records for ASN: ". $query ."</b> <br><br>";
        $sql = "SELECT * FROM pdns WHERE (asn= :query) $qtype $qttl $qsort LIMIT $DBLIMIT";
        $input_arr[':query'] = $query;
    } else {
        echo "<b>Passive DNS Records for Domain: ". $query ."</b> <br><br>";
        $sql = "SELECT * FROM pdns WHERE (query LIKE :query OR query LIKE :query1) $qtype $qttl $qsort LIMIT $DBLIMIT";
        $input_arr[':query'] = $query;
        $input_arr[':query1'] = "%$query";
    }
    $stmt = $pdo->prepare($sql);
    $stmt->execute($input_arr);
    if($stmt->rowCount() == 0){
        echo "<b>No records found...</b><br><br>";
    } else {
        echo "<table cellpadding='2'><tr><td>#</td><td><b>First Seen</b></td><td><b>Last Seen</b></td><td><b>Type</b></td><td><b>TTL</b></td><td><b>Query</b></td><td><b>Answer</b></td><td><b>ASN</b></td><td><b>Count</b></td></tr>";
        echo '
            ';
        while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
            echo "<tr>";
            echo "<td>". $cnt.".</td>";
            echo "<td>". str_replace(' ', '&nbsp;', $r['FIRST_SEEN']) ."</td>";
            echo "<td>". str_replace(' ', '&nbsp;', $r['LAST_SEEN']) ."</td>";
            echo "<td>". $r['MAPTYPE'] ."</td>";
            echo "<td><div style='word-break:break-all;'><a href='?query=". urlencode($r['QUERY']) ."&amp;type=". urlencode($type)."&amp;compare=". urlencode($compare)  ."&amp;ttl=". urlencode($ttl) . "&amp;sort=" .  urlencode($sort) . "&amp;dir=" .  urlencode($dir). "'>". strtolower(($r['QUERY'] == '') ? '.' : $r['QUERY'] ) ."</a></div></td>";
            echo "<td><div style='word-break:break-all;'><a href='?query=". urlencode($r['ANSWER']) . "&amp;type=". urlencode($type)."&amp;compare=". urlencode($compare)  ."&amp;ttl=". urlencode($ttl) . "&amp;sort=" .  urlencode($sort) . "&amp;dir=" .  urlencode($dir). "'>". strtolower($r['ANSWER']) ."</a></div></td>";
            echo "<td>". $r['TTL'] ."</td>";
            echo "<td><a href='?query=". urlencode($r['asn'])."&amp;type=". urlencode($type)."&amp;compare=". urlencode($compare)  ."&amp;ttl=". urlencode($ttl) . "&amp;sort=" .  urlencode($sort) . "&amp;dir=" .  urlencode($dir). "'>". $r['asn'] ."</a></td>";
            echo "<td>". $r['COUNT'] ."</td>";
            echo "<td><a target='_new' href='http://{$r['QUERY']}'><img src='link.png' title='go to site' alt='go to site'></a></td>";
            echo "<td><a target='_new' href='dig.php?query=" . urlencode($r['QUERY']) . "&amp;type=any'><img src='dig.png' title='dig site' alt='dig site'></a></td>";
            echo "</tr>";
            $cnt++;
        }
    }

  echo "</center>";
}

print_tail();


function sanitize($in) 
{
  $qvar =  strip_tags(addslashes(trim(getVar($in))));
  
  if ( preg_match('/(\w+\.)*\w{2,}\.\w{2,4}$/i', $qvar) ) {
    /* Might be a domain */
    return $qvar;
  } else if (preg_match('/^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]|\*)\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]|\*)\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5]|\*)$/', $qvar) ) {
    /* Might be a IPv4 */
    return $qvar;
  } else if (preg_match('/^[a-f0-9]{1,4}:((\*|([a-f0-9]{0,4}):){1,6}(\*|([a-f0-9]{1,4})))$/i', $qvar)) {
    /* FE80:0000:0000:0000:0202:B3FF:FE1E:8329 or FE80::0202:B3FF:FE1E:8329 */
    /* or even 2001:db8::1 or 0:0:0:0:0:ffff:192.1.56.10  */
    /* Might be a IPv6 */
    return $qvar;
  } elseif (is_numeric($qvar) ) {
      return $qvar;
  } elseif (strlen($qvar) > 2) {
      $qvar = str_replace('%', '', $qvar);
      return "%$qvar%";
  } elseif ($qvar == '*') {
      return '%';
  } else {
      return '';
  }
}


function print_search_body($query, $type, $compare, $sort, $dir, $ttl) 
{
    echo '<table  cellpadding="2" cellspacing="0">';
    echo '<tr><td><center><form name search method="GET">';
    echo '<input type="text" maxlength="300" name="query" placeholder="Domain/IP" value="'. $query.'">&nbsp;';

    print_select('type', array(
                'basic'=>'basic',
                'any'=> 'any', 
                'a'=> 'a',
                'aaaa'=>'aaaa',
                'cname'=>'cname',
                'dname'=> 'dname',
                'dnskey'=>'dnskey', 
                'ds'=> 'ds', 
                'gpos'=> 'gpos',
                'hinfo'=> 'hinfo',
                'loc'=> 'loc',
                'mx'=>'mx',
                'naptr'=>'naptr',
                'ns'=>'ns', 
                'nsec'=>'nsec',
                'nsec3'=>'nsec3', 
                'nsec3param'=> 'nsec3param',
                'ptr'=>'ptr',
                'rp'=>'rp', 
                'rrsig'=>'rrsig',
                'soa'=>'soa',
                'srv'=>'srv',
                'sshfp'=>'sshfp',
                'txt'=>'txt',
                    ), 'Type', $type);
    echo '<input type="text" maxlength="10" size=4 name="ttl" placeholder="TTL" value="'. $ttl .'">&nbsp;';
    print_select('compare', array('eq'=>'==', 'le'=>'&lt;=', 'ge'=> '&gt;='), 'Compare', $compare);
    print_select('sort', array(''=> '', 'FIRST_SEEN' =>'first seen', 'LAST_SEEN' =>'last seen', 'MAPTYPE' =>'type', 'TTL' =>'ttl', 'QUERY' =>'query', 'ANSWER' =>'answer', 'COUNT' =>'count', 'asn'=>'ASN'), 'Sort', $sort);
    print_select('dir', array(''=> '', 'desc' =>'Desc', 'asc' =>'Asc'), 'Dir', $dir);
    echo '<input type="submit" value="Search"></form><center><br> ';
}


