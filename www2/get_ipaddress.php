<?php 

$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";
$pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);


$sql = "select distinct answer as ip from pdns where maptype='a' and asn is null order by answer";
$sql1 = "select distinct answer as ip from pdns where maptype='aaaa' and asn is null order by answer";
$domains = $pdo->prepare($sql);
$domains->execute();
$domains1 = $pdo->prepare($sql1);
$domains1->execute();

echo "begin\n";
while ( $r = $domains->fetch(PDO::FETCH_ASSOC) ) {
    echo $r['ip'] . "\n";
}
while ( $r =$domains1->fetch(PDO::FETCH_ASSOC)) {
    echo $r['ip'] . "\n";
}

echo "end\n";


