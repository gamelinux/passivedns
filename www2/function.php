<?php


$rr_types = array(
    'basic'=>'basic',
    'any'=> 'any', 
    'a'=> 'a',
    'aaaa'=>'aaaa',
    'caa'=>'caa',
    'cds'=>'cds',
    'cert'=>'cert',
    'cname'=>'cname',
    'dhcid'=> 'dhcid',
    'dlv'=> 'dlv',
    'dname'=> 'dname',
    'dnskey'=>'dnskey', 
    'ds'=> 'ds', 
    'gpos'=> 'gpos',
    'hinfo'=> 'hinfo',
    'ipseckey'=> 'ipseckey',
    'kx'=>'kx',
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
    'spf'=>'spf',
    'srv'=>'srv',
    'sshfp'=>'sshfp',
    'tlsa'=>'tlsa',
    'txt'=>'txt',
);



$TOPLIMIT = 100;
function print_header() 
    
{
    global $TOPLIMIT;
  echo <<<HDR1
<html>
<head>
<link rel="stylesheet" href="dns.css" type="text/css">

<title id="ttag">PassiveDNS</title>
HDR1;
  echo <<<HDR2
  </head>
  <body><center>
  <div style="width: 100%;" id="menudiv" class="box">
   <a href="index.php">Home</a>&nbsp;|&nbsp;
   <a href="index.php?query=*&amp;type=&amp;ttl=&amp;compare=eq&amp;sort=LAST_SEEN&amp;dir=desc">Latest</a>&nbsp;| 
   <a href="index.php?query=*&amp;type=&amp;ttl=&amp;compare=eq&amp;sort=FIRST_SEEN&amp;dir=desc">Newest</a> | 
   <a href="plot2.php?type=length">Domains&nbsp;length</a> |
   <a href="plot2.php?type=tld&amp;sort=cnt">TLDs</a> | 
   <a href="plot2.php?type=sld">SLDs</a> | 
   <a href="plot2.php?type=rrtype&amp;sort=rrtype">RRs</a> |
   <a href="plot2.php?type=ttl&amp;sort=ttl">TTLs</a> |
   <a href="plot2.php?type=asn">ASNs</a> |
   <a href="plot2.php?type=asn_answer">ASNs&nbsp;per&nbsp;domain</a> |
   <a href="plot2.php?type=first_seen">First&nbsp;seen</a> |
   <a href="plot2.php?type=last_seen">Last&nbsp;seen</a> |
   <a href="plot2.php?type=days">Days&nbsp;active</a> |
   <a href="plot2.php?type=hour">Queries/hour</a> |
   <a href="plot2.php?type=top_request">Requests&nbsp;top&nbsp;$TOPLIMIT</a> |
   <a href="plot2.php?type=top_domain">Domains&nbsp;top&nbsp;$TOPLIMIT</a> |
   <a href="plot2.php?type=top_ip&amp;subtype=ipv4">IPv4s&nbsp;top&nbsp;$TOPLIMIT</a> |
   <a href="plot2.php?type=top_ip&amp;subtype=ipv6">IPv6s&nbsp;top&nbsp;$TOPLIMIT</a> |
   <a href="stats.php">Stats</a> |
   <a href="dig.php">Dig</a> 
  </div>
HDR2;
}


function print_select($name, $options, $placeholder = '', $selected='')
{
    echo "<select name='$name' placeholder='$placeholder'>";
    foreach($options as $k => $v) {
        echo "<option value='$k' " . (($selected == $k)? "selected='selected'": '') . ">$v</option>\n";
    }
    echo "</select>&nbsp;\n";
}

function getVar($in) {

    if (isset($_POST[$in])) {
        $out = $_POST[$in];
    } else if (isset($_GET[$in])){
        $out = $_GET[$in];
    } else 
        $out = NULL;

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

function print_tail() {
  echo '
</center>
</body>
</html>';
}


function load_tlds($pdo)
{
    $tlds = array();
    $sql = 'SELECT ID, tld from tlds';
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $t = $r['tld'];
        $tlds[$t] = $t;
    }

    return $tlds;
}


function load_domains_with_tld($pdo, $withtld)
{
    $domains = array();
    $tlds = load_tlds($pdo);
    $sql = "SELECT distinct query FROM pdns WHERE maptype != 'PTR'";
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    while ( $r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $name = $r['query'];
        $elems = explode('.', $name);
        $tld = '';
        $curr = '';
        while ($elems != array() ) {
            $t = implode('.', $elems);
            if (isset ($tlds [ $t])) {
                $tld = $t;
                $sld = $curr;
                break;
            }
            $curr = array_shift($elems);
        }
        if ($withtld) {
            $domains[] = array('name' => substr($name, 0, -strlen($tld)), 'tld' => $tld, 'sld' => $sld . '.' . $tld);
        } else {
            $domains[] = array('name' => substr($name, 0, -strlen($tld)), 'tld' => $tld, 'sld' => $sld);
        }
    }

    return $domains;
}




