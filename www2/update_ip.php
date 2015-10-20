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
    $sql_u = "UPDATE pdns set asn = :as WHERE answer = :ip";
    echo "Updating '$ip' with ASN: $as\n"; 
    $stmt = $pdo->prepare($sql_u);
    $stmt->execute(array(':as'=> $as, ':ip'=> $ip));
    $cnt ++;
}

echo "\n";
echo "Updated $cnt IP addresses\n\n";


