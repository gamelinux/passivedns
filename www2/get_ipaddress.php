<?php 

$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";
$pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);


$sql = "select distinct answer as ip from pdns where maptype in ('a', 'aaaa') and asn is null order by answer";
$domains = $pdo->prepare($sql);
$domains->execute();

echo "begin\n";
while ( $r = $domains->fetch(PDO::FETCH_ASSOC) ) {
    echo $r['ip'] . "\n";
}

echo "end\n";


