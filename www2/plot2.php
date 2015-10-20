<?php

require "function.php";

$data = array_merge($_GET, $_POST);

$data_str = '';

foreach ($data as $var => $val) {
    $data_str .= "data.$var = '$val';\n";
}

print_header();

echo <<<HTML

<!--script src="chart.js"></script>
<script src="Chart.StackedBar.js"></script-->
<script src="jquery-2.1.4.min.js"></script>
<script src="ChartNew.js"></script>
<div id="titlebar">
<span id="title" class="title"></span>
<span id="options" class="options"></span>
</div>
<canvas id="myChart"></canvas>

<script>

var width = $(document).width() - 20;
var height = $(document).height() - 5;
var shorten_height = (height > 640 ? 20 : 12);
var ctx = $("#myChart").get(0).getContext("2d");

var url = 'plot_data.php';
var data = {};
var options = {
    scaleFontSize: 10,
    barValueSpacing : 2,
    scaleShowVerticalLines: false,
   // annotateLabel: "<%=v1%> <%=v2%>: <%=v3%> (<%=v6%>%)", 
    annotateLabel: annotateAllX,
    annotateDisplay: true,
    fmtXLabel: shorten_height,
    yAxisMinimumInterval: 1,
   //annotateRelocate: true,
    graphMin : 0,
    //multiTooltipTemplate: "<%if (datasetLabel){%><%=datasetLabel%>: <%}%>: <%= value %>"
   };
$data_str

function annotateAllX(area,ctx,data,statData,posi,posj,othervars) {
    var retstring = '';
    if (data.datasets.length == 1) { 
        retstring = statData[0][posj].v2 + ": "+statData[0][posj].datavalue + "<br>";
    } else {
        retstring="<b>" + statData[posi][posj].v2 + '</b><br>';

        for(var i=0;i<data.datasets.length;i++){
            if(typeof statData[i][posj].v3 != "undefined" && data.datasets[i].type != "Line") {
                retstring = retstring + statData[i][posj].v1 + ": " + statData[i][posj].datavalue + "<br>";
            }
        }
    }
    return retstring;
}


function fmtChartJSPerso(config, val, fmt)
{
    val = ""+val;
    console.log(val, fmt);
    return val.substr(-1 * fmt);
}

$.post(url, data).done(function(html) {
   // console.log(html);
    var x = $.parseJSON(html);
    $('#title').text(x.title);
    $('#ttag').text('Passive DNS - ' + x.title);

    var colors = [ 
    "0,200,240",
    "0,200,220",
    "0,200,200",
    "0,200, 180",
    "0,200, 160",
    "0,200, 140",
    "0,200, 120",
    "0,200, 100",
    "0,200, 80",
    "0,200, 60",
    "0,200, 40",
    "0,100, 240",
    "0,100, 220",
    "0,100, 200",
    "0,100, 180",
    "0,100, 160",
    "0,100, 140",
    "0,100, 120",
    "0,180, 100",
    "0,100, 80",
    "0,40, 60",
   // "0,40, 40",
    "0,40, 240",
    "0,40, 220",
    "0,40, 200",
    "0,40, 180",
    "0,40, 160",
    "0,40, 140",
    "0,40, 120",
    "0,40, 100",
    "0,40, 80",
    "0,40, 60",
    "0,40, 40",

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
       // console.log(x.data2);
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
    if (x.options !== undefined && !$.isEmptyObject(x.options)) {
        var s= '<form action="plot2.php" method="get">Options: ';
        //console.log(x.options);

        for (var idx in x.options) {
            s = s + '<select id="'+ idx +'" name="' + idx + '"> ' ;
            s = s + '<option value="" disabled selected>' + idx + '</option>';
            for (var i in x.options[idx]) {
                s = s + '<option value="'+ [i] + '">' + x.options[idx][i] + '</option>';
            };
            s = s + "<input type='hidden' id='type' name='type' value='" + x.type+ "'>";
            s = s + '</select>&nbsp;';
        }
        s = s + "<input type='submit' id='submit' value='submit'>";
        s = s + '<form>';
        $('#options').html(s);

    }
    var posy = $("#myChart").position().top;
    var posy2 = $("#titlebar").position().top;
    $("#myChart").attr({width: width});
    $("#myChart").attr({height: height - (posy+posy2)});
    var myBarChart;
   // console.log(width, height);
    //console.log(data);
    if (stacked) {
        myBarChart = new Chart(ctx).StackedBar(data, options);
    } else {
        myBarChart = new Chart(ctx).Bar(data, options);
    }
    });
</script>

HTML;

echo "</body></html>";

