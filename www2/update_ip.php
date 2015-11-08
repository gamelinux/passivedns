<?
$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";
$pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);
$cnt = 0;
while (!feof(STDIN)) {
    $line = fgets(STDIN);
    $arr = explode('|', $line);
    $arr = array_map("trim", $arr );
    if (!is_numeric($arr[0])) continue;
    $as = $arr[0];
    $ip = $arr[1];
    $owner = trim($arr[2]);
    if ($owner == '') $owner = '?';
    $sql_u = "UPDATE pdns set asn = :as, asn_owner = :owner WHERE answer = :ip";
    echo "Updating '$ip' with ASN: $as ($owner)\n"; 
    $stmt = $pdo->prepare($sql_u);
    $stmt->execute(array(':as'=> $as, ':ip'=> $ip, ':owner'=>$owner));
    $cnt ++;
}

echo "\n";
echo "Updated $cnt IP addresses\n\n";


