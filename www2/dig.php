<?php


require "function.php";

$query = getVar('query'); if (empty($query)) $query = "";
$type = getVar("type"); if (empty($type)) $type = "";
$server = getVar("server"); if (empty($server)) $server = "";

print_header();
print_search_body($query, $type, $server);

if ($query != '' && $type != '') {
    $output = get_dig_results($query, $type, $server);
    echo "<table> <tr><td> ";
    foreach($output as $line) { 
        echo $line . "<br>";
    }
    echo "</td></tr></table>";
}



print_tail();

function get_dig_results($name, $type, $server)
{
    $name = escapeshellarg(trim($name));
    $type = escapeshellarg(trim($type));
    if ($server != '') {
        $server = '@' . escapeshellarg(trim($server));
    }


    $dig_cmd = "dig +nocmd +nostats $server -t $type $name";

    exec($dig_cmd, $output, $rv);

    return $output;
}


function print_search_body($query, $type, $server = '') 
{
    global $rr_types;
    $rr = $rr_types;
    unset($rr['basic']);
    echo '<table  cellpadding="2" cellspacing="0">';
    echo '<tr><td><center><form name search method="GET">';
    echo '<input type="text" maxlength="300" name="query" placeholder="Domain/IP" value="'. $query.'">&nbsp;';

    print_select('type', $rr, 'Type', $type);
    echo '<input type="text" maxlength="100" name="server" placeholder="DNS Server" value="'. $server.'">&nbsp;';
    
    echo '<input type="submit" value="Search">';
    echo '</form><center><br> ';
}

