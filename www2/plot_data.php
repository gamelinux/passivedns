<?php
require "function.php";


$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";

$pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);
$type = getVar('type');
$subtype = getVar('subtype');
$source = getVar('source');
$sql = "select count(*) as cnt, count(distinct query) as cnt_d from pdns";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row = $stmt->fetch(PDO::FETCH_ASSOC);
$total_count = $row['cnt'];
$distinct_count = $row['cnt_d'];

$labels = $data2 = $data = $options = array();
$legend = '';
$sort = getVar('sort');
if ($type == 'tld') {
    $limit = '';
    if ($sort == 'tld') { $sort = 'tld asc'; }
    else {$sort = 'cnt desc'; $limit = "LIMIT $TOPLIMIT"; }
    $perc = false;
    if ($subtype == 'perc') { $perc = true; }
    $title = 'Top level domains';
    $sql = "SELECT count(*) as cnt, substring_index(query, '.', -1) as tld from (select query from pdns group by query, maptype) as foo group by tld order by $sort $limit";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['tld'] == '') continue;
        if ($perc) { 
            $data[] = round(100*( $r['cnt'] / $distinct_count), 1);
        } else {
            $data[] =  $r['cnt'];
        }
        $labels[] = $r['tld'];
    }
    $options = array(
            'sort' => array( 'cnt'=>'count', 'tld'=>'TLD'),
            'subtype' => array('tld'=>'TLD','perc'=>'Percentage' )
    );
} elseif ($type == 'sld') {
    $title = 'Second level domains';
    $withtld =  false;
    if ($subtype == 'withtld') { $withtld = true;}

    $domains = load_domains_with_tld($pdo, $withtld); 
    $slds = array();
    foreach ($domains as $r) {
        if (isset($slds[ $r ['sld'] ])) { $slds[ $r ['sld'] ] ++;} else { $slds[ $r ['sld'] ] = 1;}
    }
    arsort ($slds, SORT_NUMERIC);
    $slds = array_slice($slds, 0, $TOPLIMIT);

    $data = array();
   foreach ($slds as $k => $r) {
       $data[] = $r;
       $labels[] = $k;
   }
    $options = array(
            'subtype' => array('withtld'=>'With TLD','notld'=>'Without TLD' )
    );
} elseif ($type == 'length') {
    $perc=false;
    if ($sort == 'len') { $sort = 'len asc';}
    else {$sort = 'cnt desc';}
    if ($subtype == 'perc') { $perc = true;}
    $title = 'Domain name length';
    $sql = "SELECT count(*) AS cnt, length(query) AS len FROM (select distinct query from pdns WHERE maptype != 'PTR') AS foo GROUP BY length(query) ORDER BY $sort LIMIT $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['len'] == '') continue;
        if ($perc) {
            $data[] = round(100* ($r['cnt'] / $distinct_count), 2);
        } else {
            $data[] = $r['cnt'];
        }
        $labels[] = $r['len'];
    }
    $options = array(
            'sort' => array( 'cnt'=>'count', 'len'=>'Length'),
            'subtype' => array('len'=>'Length','perc'=>'Percentage' )
    );
} elseif ($type == 'asn') {
    if ($sort == 'asn') { $sort = 'asn asc';}
    else {$sort = 'cnt desc';}
    $title = 'Domains per ASNs';
    $sql = "SELECT count(*) as cnt, asn from pdns group by asn order by $sort limit $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['asn'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = $r['asn'];
    }

    $options = array(
            'sort' => array( 'cnt'=>'count', 'asn'=>'ASN'),
    );
} elseif ($type == 'asn_answer') {
    $title = 'ASNs per domain name';
    $sql = "select count(distinct asn) as cnt, QUERY from pdns where not asn is null group by query order by cnt desc limit $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['QUERY'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = ($r['QUERY']==''?'.':$r['QUERY']);
    }
} else if ($type == 'hour') { 
    $title = 'Queries per hour';
    $where = '';
    $input_arr =array();
    if ($source == 'last') { $col = 'last_seen';} else {$col = 'first_seen';}
    if ($subtype == 'basic') {
        $where = "AND (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = "AND maptype = :subtype";
    }
    $sql = "select count(*) as cnt, hour($col) as hours, maptype from pdns WHERE 1=1  $where group by hour($col), maptype order by maptype, hours desc";
//    echo $sql;
    $stmt = $pdo->prepare($sql);
    $stmt->execute($input_arr);
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $data[$r['maptype']][$r['hours']] = array($r['hours'], $r['cnt'], $r['maptype']);
    }
    $temp = array(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
    $data2 = array();
    foreach ($data as $mapt=>$values) {
        $t = $temp;
        foreach($values as $hour=>$val) {
            $t[$hour] = $val[1];
        }
        $data2[] = array('data' => $t, 'legend'=>$mapt);
    }

    $foo = array_shift($data2);
    $legend = $foo['legend'];
    $data = $foo['data'];

    $labels = range(0, 23);
    $options = array(
            'source' => array('last'=>'Last seen','first'=>'First seen' ),
            'subtype' => $rr_types
    );
} else if ($type == 'ttl') {
    $title = 'TTL values';
    if ($sort == 'ttl') { $sort = 'nttl asc';}
    else {$sort = 'cnt desc';}
    $where = '';
    $input_arr = array();
    if ($subtype == 'basic') {
        $where = "AND (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = "AND maptype = :subtype";
    }
    $sql = "(SELECT ttl as nttl, count(*) as cnt from pdns where ttl < 300 $where group by ttl) union ( SELECT round((ttl/50))*50 as nttl, count(*) as cnt from pdns where ttl >= 300 $where group by round(ttl/50)) order by $sort";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($input_arr);
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['nttl'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = $r['nttl'];
    }
    $options = array(
            'sort' => array('ttl'=>'TTL', 'cnt'=>'count', ),
            'subtype' => $rr_types
    );
} else if ($type == 'days') {
    $title = 'Days active';
    $where = '';
    $input_arr = array();
    if ($subtype == 'basic') {
        $where = "AND (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = "WHERE maptype = :subtype";
    }

    $sql = "select count(*) as cnt, to_days(last_seen) - to_days(first_seen) as days from pdns $where group by days order by days desc";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($input_arr);
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['days'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = $r['days'];
    }
    $options = array(
            'subtype' => $rr_types
    );
} else if ($type == 'first_seen') {
    $title = 'Days since first seen';
    $where = '';
    $input_arr = array();
    if ($subtype == 'basic') {
        $where = "AND (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = "WHERE maptype = :subtype";
    }
    $sql = "select count(*) as cnt, to_days(now()) - to_days(first_seen) as days from pdns $where group by days order by days desc";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($input_arr);
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['days'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = $r['days'];
    }
    $options = array(
            'subtype' => $rr_types
    );
} else if ($type == 'last_seen') {
    $title = 'Days since last seen';
    $where = '';
    $input_arr = array();
    if ($subtype == 'basic') {
        $where = "AND (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = "WHERE maptype = :subtype";
    }
    $sql = "select count(*) as cnt, to_days(now()) - to_days(last_seen) as days from pdns $where group by days order by days desc";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($input_arr);
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['days'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = $r['days'];
    }
    $options = array(
            'subtype' => $rr_types
    );
} else if ($type == 'rrtype') {
    $title = 'Resource records';
    if ($sort == 'rrtype') { $sort = 'maptype asc';}
    else {$sort = 'cnt desc';}
    $sql = "SELECT count(*) as cnt, maptype from pdns group by maptype order by $sort";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    $labels = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($subtype == 'perc') {
            $data[] = round(($r['cnt']/$total_count) * 100, 1);
        } else {
            $data[] = $r['cnt'];
        }
        $labels[] = $r['maptype'];
    }
    $options = array(
            'sort' => array( 'cnt'=>'Count', 'rrtype'=>'RR Type'),
    );
} else if ($type == 'top_request') { 
    $title = "$TOPLIMIT frequestly requests domains";
    $sql = "SELECT max(count) as mx,sum(COUNT) as cnt, QUERY, round(sum(count)/(abs(unix_timestamp(min(first_seen))- unix_timestamp(max(last_seen)))/(24*3600))/count(*)) AS avg from pdns group by QUERY order by cnt desc limit $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $legend = 'total';
        $labels[] = ($r['QUERY']==''?'.':$r['QUERY']);
        $data [] = $r['cnt'];
        $data2['data'][] =  $r['mx'];
        $data3['data'][] =  $r['avg'];
    }
    $data2['legend'] = 'max';
    $data3['legend'] = 'avg/hr';
    $data2 = array($data2, $data3);
} else if ($type == 'top_domain') {
    $title = "Domain names with the most IP addresses";
    $sql = "SELECT count(*) AS cnt, QUERY from pdns group by query order by cnt desc limit $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $data[] = $r['cnt'];
        $labels[] = ($r['QUERY']==''?'.':$r['QUERY']);
    }
} else if ($type == 'top_ip') {
    if ($subtype == 'ipv4') {
        $title = "IPv4 addresses with the most domain names top $TOPLIMIT";
        $sql = "SELECT count(*) as cnt, answer from pdns where maptype = 'a' group by answer order by cnt desc limit $TOPLIMIT";
    } elseif ($subtype == 'ipv6') {
        $title = "IPv6 addresses with the most domain names top $TOPLIMIT";
        $sql = "SELECT count(*) as cnt, answer from pdns where maptype = 'aaaa' group by answer order by cnt desc limit $TOPLIMIT";
    } else {
        $title = "IP addresses with the most domain names top $TOPLIMIT";
        $sql = "SELECT count(*) as cnt, answer from pdns where maptype = 'a' or maptype = 'aaaa' group by answer order by cnt desc limit $TOPLIMIT";
    }
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $data[] = $r['cnt'];
        $labels[] = $r['answer'];
    }
} else {
    die ("Unknown type");
}

$vars = array('labels' => $labels, 'data'=>$data, "title" =>$title, 'legend'=> $legend, 'options' => $options, 'type'=> $type);
if ($data2 != array()) {
    $vars['data2'] = $data2;
}
die(json_encode($vars));


