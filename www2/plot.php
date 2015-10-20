<?php

require "function.php";


$data = http_build_query(array_merge($_GET, $_POST));

print_header();

echo "<div class='centered'><img src='plot_tld.php?$data' width='1200' height='768'></div>";
echo "</body></html>";

