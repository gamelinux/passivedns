<?php


$DATABASE = "127.0.0.1";
$DBUSER   = "pdns";
$DBTABLE  = "pdns";
$DBPASSWD = "pdns";
$pdo = new PDO("mysql:host=$DATABASE;dbname=$DBTABLE", $DBUSER, $DBPASSWD);

$tld_url = 'https://www.publicsuffix.org/list/public_suffix_list.dat';

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $tld_url);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);;
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$data = curl_exec($ch);

if ($data=== false){
    var_dump(curl_error($ch));
    die("Could not load URL");
}

$data = explode("\n", $data);

$insert= $updated = 0;

foreach ($data as $line) {
    $line = trim($line);
    if ($line == '' || substr($line, 0, 2) == '//') continue;
    $length = strlen($line);
    $sql = "SELECT ID from tlds WHERE tld = :line LIMIT 1";
    $tld = $pdo->prepare($sql);
    $tld->execute(array(':line'=> $line));
    if($tld->rowCount()==0) {
        $insert++;
        $sql = "INSERT INTO tlds set tld = '$line', tick = 1, length = $length";

    } else {
        $updated++;
        $row = $tld->fetch(PDO::FETCH_ASSOC);
        $id = $row['ID'];
        $sql = "UPDATE tlds set tick = 1, length = $length WHERE ID = $id";
    }
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
}

$sql = "delete from tlds where tick != 1";
$stmt = $pdo->prepare($sql);
$stmt->execute();
$sql = "update tlds set tick = 0";
$stmt = $pdo->prepare($sql);
$stmt->execute();

echo "Updated $updated and inserted $insert TLDs\n\n";

curl_close($ch);
