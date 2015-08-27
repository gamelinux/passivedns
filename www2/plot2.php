<?php

require "function.php";

$data = array_merge($_GET, $_POST);

$data_str = '';

foreach ($data as $var => $val) {
    $data_str .= "data.$var = '$val';\n";
}

print_header();

echo <<<HTML

<script src="chart.js"></script>
<script src="Chart.StackedBar.js"></script>
<script src="jquery-2.1.4.min.js"></script>
<span id="title"></span><br/>
<canvas id="myChart"></canvas>
<script >

var ctx = $("#myChart").get(0).getContext("2d");
var width = $(document).width() - 10;
var height = $(document).height() - 10;
var posy = $("#myChart").position().top;
$("#myChart").width(width);
$("#myChart").height(height - posy);
var url = 'plot_data.php';
var data = {};
var options = {
    scaleFontSize: 10,
    barValueSpacing : 2,
    scaleShowVerticalLines: false,
    multiTooltipTemplate: "<%if (datasetLabel){%><%=datasetLabel%>: <%}%>: <%= value %>"
   };
$data_str

$.post(url, data).done(function(html) {
        console.log(html);
    var x = $.parseJSON(html);
    $('#title').text(x.title);
    $('#ttag').text('Passive DNS - ' + x.title);

    var colors = [ 
    "0,160,200",
    "0,200, 160",
    "0,120, 200",
    "0,200, 120",
    "200, 0, 160",
    "200, 0, 120",
    "200, 160, 0",
    "200, 120, 0",
    "200, 120, 160",
    "200, 160, 160",
    "200, 120, 120",
    "200, 160, 120",
    ];

    data = {
        labels: x.labels,
        datasets: [ { 
                label: x.legend,
                fillColor: "rgba(" + colors[0] + ", 0.5)",
                strokeColor: "rgba(" + colors[0] + ",0.8)",
                highlightFill: "rgba("  + colors[0] +",0.75)",
                highlightStroke: "rgba(" + colors[0] +",1)",
                data: x.data
        } ]
    };
    var stacked = false;
    if (x.data2 !== undefined) {
        stacked = true;
        var temp;
        var i=1;
        console.log(x.data2);
        x.data2.forEach( function (s) { 
            temp =  { 
                label: s.legend,
                fillColor: "rgba(" + colors[i] + ", 0.5)",
                strokeColor: "rgba(" + colors[i] + ",0.8)",
                highlightFill: "rgba("  + colors[i] +",0.75)",
                highlightStroke: "rgba(" + colors[i] +",1)",
                data: s.data
            } ;
            data.datasets.push(temp);
            i = (i + 1) % colors.length;
        } );
    }
    var myBarChart;
    if (stacked) {
        myBarChart = new Chart(ctx).StackedBar(data, options);
    } else {
        myBarChart = new Chart(ctx).Bar(data, options);
    }
    });
</script>

HTML;

echo "</body></html>";

