<?php


require "function.php";

$query = getVar('query'); if (empty($query)) $query = "";
$type = getVar("type"); if (empty($type)) $type = "";

print_header();

print_search_body($query, $type);

if ($query != '' && $type != '') {
    $output = get_dig_results($query, $type);
    echo "<table> <tr><td> ";
    foreach($output as $line) { 
        echo $line . "<br>";
    }
    echo "</td></tr></table>";
}



print_tail();

function get_dig_results($name, $type)
{
    $name = escapeshellarg($name);
    $type = escapeshellarg($type);


    $dig_cmd = "dig +nocmd +nostats @localhost -t $type $name";

    exec($dig_cmd, $output, $rv);

    return $output;
}





function print_search_body($query, $type) 
{
    echo '<table  cellpadding="2" cellspacing="0">';
    echo '<tr><td><center><form name search method="GET">';
    echo '<input type="text" maxlength="300" name="query" placeholder="Domain/IP" value="'. $query.'">&nbsp;';

    print_select('type', array(
                'any'=> 'any', 
                'a'=> 'a', 
                'aaaa'=>'aaaa', 
                'axfr'=>'axfr', 
                'cname'=>'cname',
                'dname'=> 'dname',
                'dnskey'=> 'dnskey',
                'ds'=> 'ds',
                'gpos'=> 'gpos',
                'hinfo'=> 'hinfo',
                'key'=> 'key',
                'loc'=> 'loc',
                'mx'=>'mx', 
                'naptr'=>'naptr',
                'ns'=>'ns', 
                'nsec'=>'nsec', 
                'nsec3'=>'nsec3', 
                'nsec3param'=>'nsec3param', 
                'ptr'=>'ptr', 
                'rp'=>'rp', 
                'rrsig'=>'rrsig', 
                'soa'=>'soa', 
                'sig'=>'sig', 
                'srv'=>'srv',
                'sshfp'=>'sshfp',
                'ta'=>'ta',
                'tlsa'=>'tlsa',
                'tsig'=>'tsig',
                'txt'=>'txt'),
            'Type', $type);
    
    echo '<input type="submit" value="Search"></form><center><br> ';
}

