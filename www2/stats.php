<?php

require "function.php";
$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";

$pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);
$sql = "select count(*) as cnt2, count(distinct query) as cnt , count(distinct answer) as cnt1 from pdns";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row =  $stmt->fetch(PDO::FETCH_ASSOC);
$domains = $row['cnt'];
$answers = $row['cnt1'];
$entries = $row['cnt2'];

$sql = "select max(count) max_count, min(count) as min_count, avg(count) as avg_count, stddev(count) as std_count from pdns";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row =  $stmt->fetch(PDO::FETCH_ASSOC);
$min_count = $row['min_count'];
$max_count = $row['max_count'];
$avg_count = round($row['avg_count']);
$std_count = round($row['std_count']);

$sql = "select max(ttl) max_ttl, min(ttl) as min_ttl, avg(ttl) as avg_ttl, stddev(ttl) as std_ttl from pdns";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row =  $stmt->fetch(PDO::FETCH_ASSOC);
$min_ttl = $row['min_ttl'];
$max_ttl = $row['max_ttl'];
$avg_ttl = round($row['avg_ttl']);
$std_ttl = round($row['std_ttl']);

$sql = "select max( to_days(last_seen) - to_days(first_seen)) max_days, min( to_days(last_seen) - to_days(first_seen)) as min_days, avg( to_days(last_seen) - to_days(first_seen)) as avg_days, stddev( to_days(last_seen) - to_days(first_seen)) as std_days from pdns";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row =  $stmt->fetch(PDO::FETCH_ASSOC);
$min_days = $row['min_days'];
$max_days = $row['max_days'];
$avg_days = round($row['avg_days']);
$std_days = round($row['std_days']);

$sql = "select count(distinct asn) as cnt from pdns";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row =  $stmt->fetch(PDO::FETCH_ASSOC);
$asn_cnt = $row['cnt'];

$sql = "select count(distinct substring_index(query, '.', -1)) as cnt from pdns";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row =  $stmt->fetch(PDO::FETCH_ASSOC);
$tld_cnt = $row['cnt'];


$sld = load_domains_with_tld($pdo, FALSE); 

foreach ($sld as $r) {
    if (!isset($slds[ $r ['sld'] ])) { $slds[ $r ['sld'] ] = 1;}
}
$sld_cnt1 = count($slds);
$sld = load_domains_with_tld($pdo, TRUE); 
foreach ($sld as $r) {
    if (!isset($slds[ $r ['sld'] ])) { $slds[ $r ['sld'] ] = 1;}
}
$sld_cnt2 = count($slds);

print_header() ;


echo <<<TTT

<table>
<tr><td>Distinct entries</td><td>$entries</td>
<td>Distinct queries</td><td>$domains</td></tr>
<tr><td>Distinct answers</td><td>$answers</td></tr>

<tr><td>Min TTL</td><td>$min_ttl</td>
<td>Max TTL</td><td>$max_ttl</td></tr>
<tr><td>Average TTL</td><td>$avg_ttl</td>
<td>STD TTL</td><td>$std_ttl</td></tr>

<tr><td>Distinct ASNs</td><td>$asn_cnt</td>
<td>Distinct TLDs</td><td>$tld_cnt</td></tr>

<tr><td>Different SLDs without TLD</td><td>$sld_cnt1</td>
<td>Different SLDs with TLD</td><td>$sld_cnt2</td></tr>

<tr><td>Min Days</td><td>$min_days</td>
<td>Max Days</td><td>$max_days</td></tr>
<tr><td>Average Days</td><td>$avg_days</td>
<td>STD Days</td><td>$std_days</td></tr>

<tr><td>Min Count</td><td>$min_count</td>
<td>Max Count</td><td>$max_count</td></tr>
<tr><td>Average Count</td><td>$avg_count</td>
<td>STD Count</td><td>$std_count</td></tr>
<tr><td></td><td></td></tr>
<tr><td></td><td></td></tr>
<tr><td></td><td></td></tr>
<tr><td></td><td></td></tr>
<tr><td></td><td></td></tr>
<tr><td></td><td></td></tr>
</table>

TTT;

