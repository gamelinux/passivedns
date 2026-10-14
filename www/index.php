<?php
# --------------------------------------------------------------------------
# Copyright (C) 2013-2026 Edward Fjellskål <edward.fjellskaal@gmail.com>
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
# Local demo. Set PDNS_DB_PASSWORD before serving this page.
# Optional: PDNS_DB_HOST, PDNS_DB_USER, PDNS_DB_NAME, PDNS_WEB_TOKEN.
# PDNS_WEB_TOKEN, when set, is required on every request as ?token=.

$DBHOST = getenv('PDNS_DB_HOST');
$DBUSER = getenv('PDNS_DB_USER');
$DBNAME = getenv('PDNS_DB_NAME');
$DBPASS = getenv('PDNS_DB_PASSWORD');
$TOKEN  = getenv('PDNS_WEB_TOKEN');
if ($DBHOST === false || $DBHOST === '') $DBHOST = '127.0.0.1';
if ($DBUSER === false || $DBUSER === '') $DBUSER = 'pdns';
if ($DBNAME === false || $DBNAME === '') $DBNAME = 'pdns';

if ($TOKEN !== false && $TOKEN !== '') {
    $given = isset($_GET['token']) ? (string)$_GET['token'] : '';
    if ($given === '' || !hash_equals($TOKEN, $given)) {
        http_response_code(403);
        echo "Forbidden";
        exit;
    }
} else {
    $TOKEN = '';
}

if ($DBPASS === false || $DBPASS === '') {
    http_response_code(500);
    echo "PDNS_DB_PASSWORD is not set";
    exit;
}

$query = '';
if (isset($_GET['query']))
    $query = (string)$_GET['query'];
elseif (isset($_POST['query']))
    $query = (string)$_POST['query'];
$query = str_replace("\0", '', $query);
if (strlen($query) > 255)
    $query = substr($query, 0, 255);

print_header();
print_search_body($TOKEN);

if ($query !== '') {
    echo "<center>";
    $db = mysqli_connect($DBHOST, $DBUSER, $DBPASS, $DBNAME);
    if (!$db) {
        echo "<b>Database unavailable.</b>";
    } else {
        mysqli_set_charset($db, 'utf8mb4');
        $rows = pdns_search($db, $query);
        if ($rows === null) {
            echo "<b>Search failed.</b>";
        } elseif (count($rows) === 0) {
            echo "<b>PassiveDNS records for " . h($query) . "</b><br><br>";
            echo "<b>No records found...</b><br><br>";
        } else {
            echo "<b>PassiveDNS records for " . h($query) . "</b><br><br>";
            echo "<table cellpadding='2'><tr><td><b>First Seen</b></td><td><b>Last Seen</b></td><td><b>Type</b></td><td><b>TTL</b></td><td><b>Query</b></td><td><b>Answer</b></td><td><b>Count</b></td></tr>";
            foreach ($rows as $r) {
                echo "<tr>";
                echo "<td>" . h($r['FIRST_SEEN']) . "</td>";
                echo "<td>" . h($r['LAST_SEEN']) . "</td>";
                echo "<td>" . h($r['MAPTYPE']) . "</td>";
                echo "<td>" . h($r['TTL']) . "</td>";
                echo "<td><a href='" . qlink($r['QUERY'], $TOKEN) . "'>" . h($r['QUERY']) . "</a></td>";
                echo "<td><a href='" . qlink($r['ANSWER'], $TOKEN) . "'>" . h($r['ANSWER']) . "</a></td>";
                echo "<td>" . h($r['COUNT']) . "</td>";
                echo "</tr>";
            }
            echo "</table>";
        }
        mysqli_close($db);
    }
    echo "</center>";
}

print_tail();

function h($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function qlink($value, $token) {
    $href = '?query=' . rawurlencode((string)$value);
    if ($token !== '')
        $href .= '&token=' . rawurlencode($token);
    return h($href);
}

function like_escape($s) {
    return str_replace(array('\\', '%', '_'), array('\\\\', '\\%', '\\_'), $s);
}

function pdns_search($db, $query) {
    if (filter_var($query, FILTER_VALIDATE_IP)) {
        $sql = "SELECT FIRST_SEEN, LAST_SEEN, MAPTYPE, TTL, QUERY, ANSWER, COUNT
                FROM pdns WHERE ANSWER = ? LIMIT 500";
        $stmt = mysqli_prepare($db, $sql);
        if (!$stmt)
            return null;
        mysqli_stmt_bind_param($stmt, 's', $query);
    } else {
        $like = '%' . like_escape($query) . '%';
        $like_q = $like;
        $like_a = $like;
        $sql = "SELECT FIRST_SEEN, LAST_SEEN, MAPTYPE, TTL, QUERY, ANSWER, COUNT
                FROM pdns WHERE QUERY LIKE ? OR ANSWER LIKE ? LIMIT 500";
        $stmt = mysqli_prepare($db, $sql);
        if (!$stmt)
            return null;
        mysqli_stmt_bind_param($stmt, 'ss', $like_q, $like_a);
    }
    if (!mysqli_stmt_execute($stmt)) {
        mysqli_stmt_close($stmt);
        return null;
    }
    $first = $last = $map = $ttl = $q = $a = $count = null;
    mysqli_stmt_bind_result($stmt, $first, $last, $map, $ttl, $q, $a, $count);
    $rows = array();
    while (mysqli_stmt_fetch($stmt)) {
        $rows[] = array(
            'FIRST_SEEN' => $first,
            'LAST_SEEN' => $last,
            'MAPTYPE' => $map,
            'TTL' => $ttl,
            'QUERY' => $q,
            'ANSWER' => $a,
            'COUNT' => $count,
        );
    }
    mysqli_stmt_close($stmt);
    return $rows;
}

function print_header() {
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo "<html>
<head>
<title>PassiveDNS</title>
<meta charset=\"utf-8\">";
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
   Local demo. Set PDNS_WEB_TOKEN when this page is reachable beyond this host.
  </p>
  </div>
  <table width="860" cellpadding="2" cellspacing="0">
';
}

function print_search_body($token) {
    echo '<tr><td><center><form method="GET">';
    if ($token !== '')
        echo '<input type="hidden" name="token" value="' . h($token) . '">';
    echo 'Domain/IP: <input type="text" maxlength="255" name="query">';
    echo '<input type="submit" value="Search"></form></center><br>
';
}

function print_tail() {
    echo '
</center>
</body>
</html>';
}

?>
