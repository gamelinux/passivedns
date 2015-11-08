<?php
require "function.php";

$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";

$pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);
$type = getVar('type');
$subtype = getVar('subtype');
$use_blacklist = getVar('use_blacklist', $BLACKLIST_DEFAULT);
if (in_array(strtolower($use_blacklist), array('true', '1', 'yes'))) {
    $use_blaclist = TRUE; 
} else {
    $use_blacklist = FALSE;
}
$blacklist = '';
if ($use_blacklist) { 
    $blacklist = parse_black_list($BLACKLIST, "QUERY", $pdo);
}
$source = getVar('source');
$sql = "select count(*) as cnt, count(distinct query) as cnt_d from pdns where 1=1 $blacklist";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$row = $stmt->fetch(PDO::FETCH_ASSOC);
$total_count = $row['cnt'];
$distinct_count = $row['cnt_d'];
$plottype = 'bar';
$labels = $data2 = $data = $options = array();
$legend = '';
$sort = getVar('sort');

if ($type == 'tld') {
    $limit = '';
    if ($sort == 'tld') { $sort = 'tld asc'; }
    elseif ($sort == 'first_seen') { $sort = 'MIN(FIRST_SEEN) DESC'; }
    else {$sort = 'cnt desc'; $limit = "LIMIT $TOPLIMIT"; }
    $perc = false;
    if ($subtype == 'perc') { $perc = true; }
    $title = 'Top level domains';
    $sql = "SELECT count(*) AS cnt, substring_index(query, '.', -1) AS tld FROM (SELECT query, first_seen FROM pdns GROUP BY query, maptype) AS foo WHERE 1=1 $blacklist GROUP BY tld ORDER BY $sort $limit";
    // echo $sql;
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'sort' => array('cnt'=>'count', 'tld'=>'TLD', 'first_seen'=> 'First seen'),
        'subtype' => array('tld'=>'TLD','perc'=>'Percentage' )
    );
} elseif ($type == 'timeline') {
    $title = 'Timeline ';
    $limit = " LIMIT $TOPLIMIT";
    $sort = 'FIRST_SEEN';
    $plottype = 'timeline';
    $domain =  getVar('domain');
    $ip =  getVar('ip');
    $input_arr = array();
    if ($subtype != '') {
        $input_arr[':subtype'] = $subtype;
        $subtype = ' AND maptype LIKE :subtype ';
    }
    //var_dump($input_arr);
    if ($domain != '') {
        $input_arr[':domain'] =$domain;
        $sql = "SELECT unix_timestamp(FIRST_SEEN) AS FIRST, unix_timestamp(LAST_SEEN) AS LAST, query, answer, maptype FROM pdns WHERE query like :domain $subtype ORDER BY $sort $limit";
    } else if ($ip != '') {
        $input_arr[':domain']= $ip;
        $sql = "SELECT unix_timestamp(FIRST_SEEN) AS FIRST, unix_timestamp(LAST_SEEN) AS LAST, query, answer, maptype FROM pdns WHERE answer like :domain $subtype ORDER BY $sort $limit";
    }
    //echo $sql;
    //var_dump($input_arr);
    $stmt = $pdo->prepare($sql);
    $stmt->execute($input_arr);
    if($stmt->rowCount()==0) die("empty");
    $cnt = 0;
    $oldest = 0;
    $youngest = time();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $data[$cnt] = array('cnt'=> $cnt, 'first'=>$r['FIRST'], 'last'=> $r['LAST'], 'query'=>$r['query'], 'answer'=>$r['answer'], 'maptype'=>$r['maptype']);
        $cnt++;
        $oldest = max($oldest, $r['LAST']);
        $youngest = min($youngest, $r['FIRST']);
    }
    $options = array(
        'youngest' => $youngest - 3600,
        'oldest'=> $oldest +  3600
    );

} elseif ($type == 'sld') {
    $title = 'Second level domains';
    $withtld =  false;
    if ($subtype == 'withtld') { $withtld = true;}

    $domains = load_domains_with_tld($pdo, $withtld, $blacklist); 
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'subtype' => array('withtld'=>'With TLD','notld'=>'Without TLD' )
    );
} elseif ($type == 'length') {
    $perc=false;
    if ($sort == 'len') { $sort = 'len asc';}
    else {$sort = 'cnt desc';}
    if ($subtype == 'perc') { $perc = true;}
    $title = 'Domain name length';
    $sql = "SELECT count(*) AS cnt, length(query) AS len FROM (SELECT DISTINCT query FROM pdns WHERE maptype != 'PTR') AS foo WHERE 1=1 $blacklist GROUP BY length(query) ORDER BY $sort LIMIT $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die('empty');
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'sort' => array( 'cnt'=>'count', 'len'=>'Length'),
        'subtype' => array('len'=>'Length','perc'=>'Percentage' )
    );
} elseif ($type == 'asn') {
    if ($sort == 'asn') { $sort = 'asn asc';}
    else {$sort = 'cnt desc';}
    $title = 'Domains per ASNs';
    $sql = "SELECT count(*) AS cnt, asn, asn_owner FROM pdns WHERE 1=1 $blacklist GROUP BY asn ORDER BY $sort LIMIT $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount() == 0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['asn'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = $r['asn_owner'] . ' -- ' . $r['asn'];
    }

    $options = array(
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'sort' => array( 'cnt'=>'count', 'asn'=>'ASN'),
    );
} elseif ($type == 'asn_answer') {
    $title = 'ASNs per domain name';
    $sql = "SELECT count(distinct (ifnull(asn, rand()))) AS cnt, QUERY FROM pdns WHERE maptype IN ('A', 'AAAA') $blacklist GROUP BY query ORDER BY cnt desc LIMIT $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        if ($r['QUERY'] == '') continue;
        $data[] = $r['cnt'];
        $labels[] = ($r['QUERY']==''?'.':$r['QUERY']);
    }
    $options = array(
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
    );
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
    $sql = "SELECT count(*) AS cnt, hour($col) AS hours, maptype FROM pdns WHERE 1=1 $where $blacklist GROUP BY hour($col), maptype ORDER BY maptype, hours desc";
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
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
        $where = "AND (MAPTYPE = 'A' OR MAPTYPE = 'AAAA' OR MAPTYPE = 'CNAME' OR MAPTYPE = 'MX' OR MAPTYPE = 'NS' OR MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = "AND maptype = :subtype";
    }
    $sql = "(
            SELECT ttl as nttl, count(*) as cnt from pdns where ttl < 90 $where $blacklist GROUP BY ttl) 
                UNION (
            SELECT round((ttl/10))*10 AS nttl, count(*) AS cnt FROM pdns WHERE ttl >=90 AND ttl < 300 $where $blacklist GROUP BY round(ttl/10)) 
                UNION (
            SELECT round((ttl/100))*100 AS nttl, count(*) AS cnt FROM pdns WHERE ttl >= 300 $where $blacklist GROUP BY round(ttl/100)
            )
        ORDER BY $sort";
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'sort' => array('ttl'=>'TTL', 'cnt'=>'count', ),
        'subtype' => $rr_types
    );
} else if ($type == 'days') {
    $title = 'Days active';
    $where = 'WHERE 1=1 ';
    $input_arr = array();
    if ($subtype == 'basic') {
        $where = "AND (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = "AND maptype = :subtype";
    }
    $sql = "SELECT to_days(max(last_seen)) - to_days(min(first_seen)) AS len FROM pdns WHERE 1=1 $blacklist";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    $len = $r["len"];
    if ($len > $TOPLIMIT) {
        $t = round($len / $TOPLIMIT);
        $sql = "SELECT round(count(*)/$t) AS cnt, (round(((to_days(last_seen) - to_days(first_seen)) / $t))*$t) AS days FROM pdns $where $blacklist GROUP BY round(days/$t) ORDER BY days desc";
    } else {
        $sql = "SELECT count(*) AS cnt, to_days(last_seen) - to_days(first_seen) AS days FROM pdns $where $blacklist GROUP BY days ORDER BY days desc";
    }
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'subtype' => $rr_types
    );
} else if ($type == 'first_seen') {
    $title = 'Days since first seen';
    $where = 'WHERE 1=1 ';
    $input_arr = array();
    if ($subtype == 'basic') {
        $where = "AND (MAPTYPE = 'A' or MAPTYPE = 'AAAA' or MAPTYPE = 'CNAME' or MAPTYPE = 'MX' or MAPTYPE = 'NS' or MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = " and maptype = :subtype";
    }
    $sql = "SELECT to_days(max(last_seen)) - to_days(min(first_seen)) AS len FROM pdns WHERE 1=1 $blacklist";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    $len = $r["len"];
    if ($len > $TOPLIMIT) {
        $t = round($len / $TOPLIMIT);
        $sql = "SELECT round(count(*)/$t) AS cnt, (round(((to_days(now()) - to_days(first_seen)) / $t))*$t) AS days FROM pdns $where $blacklist GROUP BY round(days/$t) ORDER BY days desc";
    } else {
        $sql = "SELECT count(*) AS cnt, to_days(now()) - to_days(first_seen) AS days FROM pdns $where $blacklist GROUP BY days ORDER BY days desc";
    }
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'subtype' => $rr_types
    );
} else if ($type == 'last_seen') {
    $title = 'Days since last seen';
    $where = 'WHERE 1=1 ';
    $input_arr = array();
    if ($subtype == 'basic') {
        $where = " AND (MAPTYPE = 'A' OR MAPTYPE = 'AAAA' OR MAPTYPE = 'CNAME' OR MAPTYPE = 'MX' OR MAPTYPE = 'NS' OR MAPTYPE = 'SOA') ";
    } elseif ($subtype != '' && $subtype != 'any') { 
        $input_arr[':subtype'] = $subtype;
        $where = " AND maptype = :subtype";
    }
    $sql = "SELECT to_days(max(last_seen)) - to_days(min(first_seen)) AS len FROM pdns";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    $len = $r["len"];
    if ($len > $TOPLIMIT) {
        $t = round($len / $TOPLIMIT);
        $sql = "SELECT round(count(*)/$t) AS cnt, (round(((to_days(now()) - to_days(last_seen)) / $t))*$t) AS days FROM pdns $where $blacklist GROUP BY round(days/$t) ORDER BY days desc";
    } else {
        $sql = "SELECT count(*) AS cnt, to_days(now()) - to_days(last_seen) AS days FROM pdns $where $blacklist GROUP BY days ORDER BY days desc";
    }
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'subtype' => $rr_types
    );
} else if ($type == 'rrtype') {
    $title = 'Resource records';
    if ($sort == 'rrtype') { $sort = 'maptype asc';}
    else {$sort = 'cnt desc';}
    $sql = "SELECT count(*) AS cnt, maptype FROM pdns WHERE 1=1 $blacklist GROUP BY maptype ORDER BY $sort";
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
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
        'sort' => array( 'cnt'=>'Count', 'rrtype'=>'RR Type'),
    );
} else if ($type == 'top_request') { 
    $title = "$TOPLIMIT frequestly requests domains";
    $sql = "SELECT max(count) AS mx,sum(COUNT) AS cnt, QUERY, round(sum(count)/(abs(unix_timestamp(min(first_seen))- unix_timestamp(max(last_seen)))/(24*3600))/count(*)) AS avg FROM pdns WHERE 1=1 $blacklist GROUP BY QUERY ORDER BY cnt desc LIMIT $TOPLIMIT";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $legend = 'total';
        $labels[] = ($r['QUERY']==''?'.':$r['QUERY']);
        $data[] = $r['cnt'];
        $data2['data'][] =  $r['mx'];
        $data3['data'][] =  $r['avg'];
    }
    $data2['legend'] = 'max';
    $data3['legend'] = 'avg/hr';
    $data2 = array($data2, $data3);
    $options = array(
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
    );
} else if ($type == 'top_domain') {
    $title = "Domain names with the most IP addresses";

    $sql = "SELECT count(*) AS cnt, QUERY from pdns WHERE 1=1 $blacklist GROUP BY query ORDER BY cnt desc LIMIT $TOPLIMIT";
    //echo $sql;
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $data[] = $r['cnt'];
        $labels[] = ($r['QUERY']==''?'.':$r['QUERY']);
    }
    $options = array(
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
    );
} else if ($type == 'top_ip') {
    if ($subtype == 'ipv4') {
        $title = "IPv4 addresses with the most domain names top $TOPLIMIT";
        $sql = "SELECT count(*) as cnt, answer FROM pdns WHERE maptype = 'a' $blacklist GROUP BY answer ORDER BY cnt desc LIMIT $TOPLIMIT";
    } elseif ($subtype == 'ipv6') {
        $title = "IPv6 addresses with the most domain names top $TOPLIMIT";
        $sql = "SELECT count(*) as cnt, answer FROM pdns WHERE maptype = 'aaaa' $blacklist GROUP BY answer ORDER BY cnt desc LIMIT $TOPLIMIT";
    } else {
        $title = "IP addresses with the most domain names top $TOPLIMIT";
        $sql = "SELECT count(*) as cnt, answer FROM pdns WHERE maptype = 'a' OR maptype = 'aaaa' $blacklist GROUP BY answer ORDER BY cnt desc LIMIT $TOPLIMIT";
    }
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    if($stmt->rowCount()==0) die("empty");
    $data = array();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC) ) {
        $data[] = $r['cnt'];
        $labels[] = $r['answer'];
    }
    $options = array(
        'use_blacklist' => array('true'=>"Yes", 'false'=>"No"),
    );
} else {
    die ('Unknown type');
}

$vars = array('labels' => $labels, 'data'=>$data, "title" =>$title, 'legend'=> $legend, 'options' => $options, 'type'=> $type, 'plottype' => $plottype);
if ($data2 != array()) {
    $vars['data2'] = $data2;
}
die(json_encode($vars));


