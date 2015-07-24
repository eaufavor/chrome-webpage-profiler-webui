/*jshint multistr: true */

$('#check_heath_button').click(check_health);
$('#run_test_button').click(run_tests);
$('#show_results_button').click(show_results);

function check_health( event ) {
    event.preventDefault();

    $("#result-card").hide();
    $( "#output" ).text( '' ).show();
    $("#health_bar").show();
    var ip = $("#agentIP").val().trim();
    var port =  $("#agentport").val().trim();
    var url = "http://" + ip;
    if (ip.search(':')<0) {
        if (port.trim()) {
            url = url + ':' + $("#agentport").val().trim();
        }
        else {
            url = url + ':' + '8000';
        }
    }
    url = url + "/status?callback=?";

    $.ajax({
        cache:false,
        timeout:3000,
        method:"GET",
        url:url,
        dataType: "json",
        error:function(e1, e2, e3){ $("#health_bar").hide(); $("#result-card").show(); $( "#output" ).text( e2+' '+e3 ).show(); },
        success:function(data){ $("#health_bar").hide(); $("#result-card").show(); $( "#output" ).text( data.message ).show(); }
    });
}

var url;
var jobid;
var config;

function run_tests( event ) {
    event.preventDefault();

    $("#final_bar").show();
    $("#final-card").hide();
    var agentIP = $("#agentIP").val();
    var agentport = $("#agentport").val();
    var key = $("#key").val();
    var test_actions = $('input[name=test_actions]:checked', '#test-form').val();
    var test_config = $("#test_config").val();
    var query_jobid = $("#query_jobid").val();
    url = "http://" + agentIP.trim();

    if (agentIP.trim().search(':')<0) {
        if (agentport.trim()) {
            url = url + ':' + agentport.trim();
        }
        else {
            url = url + ':' + '8000';
        }
    }
    if (query_jobid) {
        jobid = query_jobid;
        check_submitted();
    }
    else {
        config = {};
        try{
            config['tests-config'] = JSON.parse($('#test_config').val());
        }catch(e){
            config['tests-config'] = null;
        }
        config.action = test_actions;
        config.key = key;
        data = JSON.stringify(config);
        $( "#final_result" ).text( url + ' key:' + key + ' action:' + test_actions  ).show();
        $.ajax({
            cache:false,
            method:"POST",
            url:url+'/async',
            data:data,
            error:function(e1, e2, e3){ $("#final_bar").hide(); $("#final-card").show(); $( "#final_result" ).text(e2+' '+e3).show(); },
            success: submitted
        });
    }
}

var cs_timeout;

function submitted( data ) {
    jobid = data['job-id'];
    if (typeof jobid === "undefined") {
        $("#inter-results").hide();
        $("#final_bar").hide();
        $("#final-card").show();
        $( "#final_result" ).text( JSON.stringify(data, null, 2) ).show();
    }
    else {
        cs_timeout = setTimeout(check_submitted, 1000);
    }
}

function check_submitted() {
    var query = {};
    query.jobid = jobid;
    $.ajax({
        cache:false,
        method:"GET",
        url:url+'/job',
        data:query,
        error:function(e1, e2, e3){ $("#final_bar").hide(); $("#final-card").show(); $( "#final_result" ).text(e2+' '+e3).show(); },
        success:check_finished
    });
}

var results_data;

function check_finished( data ) {
    if (data.status <= 0) {
        $("#inter-results").hide();
        $("#final_bar").hide();
        $("#final-card").show();
        $( "#final_result" ).text( JSON.stringify(data, null, 2) ).show();
        results_data = data;
        clearTimeout(cs_timeout);
        show_results(null);
    }
    else {
        $("#inter-results").text(data.message).show();
        cs_timeout = setTimeout(check_submitted, 1000);
    }
}

function show_results( event ) {
    if (event) {
        event.preventDefault();
    }
    $('#results_table_body').empty();
    $.each(results_data.file_groups, make_table_row);
    $.each(results_data.files, make_result_buttoms);
    $('#get_tarball').unbind( "click" );
    $('#get_tarball').click(function(){
        window.open(url+results_data.tarball, '_blank');
    });
    //$.each(['aay','ppa'], make_table_row(row));
    $("#show_results")[0].click();
}

var viewer = "http://bos-lvg5b.kendall.corp.akamai.com/index.php?inputUrl=";

function make_result_buttoms(index, value) {
    if (value.search('test.log') >= 0){
        $('#get_test_log').unbind( "click" );
        $('#get_test_log').click(function(){
            window.open(url+value, '_blank');
        });
    }
    else if (value.search('analyze.log') >= 0) {
        $('#get_analyze_log').unbind( "click" );
        $('#get_analyze_log').click(function(){
            window.open(url+value, '_blank');
        });
    }
    else if (value.search('ssl_keylog') >= 0) {
        $('#get_keys').unbind( "click" );
        $('#get_keys').click(function(){
            window.open(url+value, '_blank');
        });
    }
}

function make_table_row(index, value) {
    row = document.createElement('tr');
    col = document.createElement('td');
    col.appendChild(document.createTextNode(value.url));
    row.appendChild(col);
    var a;
    var linkText;
    col = document.createElement('td');
    if (typeof value.har !== 'undefined') {
        a = document.createElement('a');
        linkText = document.createTextNode("view");
        a.appendChild(linkText);
        a.title = "view";
        a.href = viewer+url+value.har+'p';
        a.target = "_blank";
        document.body.appendChild(a);
        col.appendChild(a);
    }
    row.appendChild(col);

    col = document.createElement('td');
    if (typeof value.pcap !== 'undefined') {
        a = document.createElement('a');
        linkText = document.createTextNode("download");
        a.appendChild(linkText);
        a.title = "download";
        a.href = url+value.pcap;
        a.target = "_blank";
        document.body.appendChild(a);
        col.appendChild(a);
    }
    row.appendChild(col);

    col = document.createElement('td');
    if (typeof value.screenshot!== 'undefined') {
        a = document.createElement('a');
        linkText = document.createTextNode("view");
        a.appendChild(linkText);
        a.title = "view";
        a.href = url+value.screenshot;
        a.target = "_blank";
        document.body.appendChild(a);
        col.appendChild(a);
    }
    row.appendChild(col);

    col = document.createElement('td');
    if (typeof value.finalhar!== 'undefined') {
        a = document.createElement('a');
        linkText = document.createTextNode("view");
        a.appendChild(linkText);
        a.title = "view";
        a.href = viewer+url+value.finalhar+'p';
        a.target = "_blank";
        document.body.appendChild(a);
        col.appendChild(a);
    }
    row.appendChild(col);


    $('#results_table_body').append(row);
}

function append_test() {
    if (typeof $('#counter').data.count === "undefined") {
        $('#counter').data.count = 0;
    }
    $('#counter').data.count = $('#counter').data.count + 1;
    var test_section = document.createElement('section');
    test_section.id = "test"+$('#counter').data.count;
    test_section.className = 'section--center mdl-grid mdl-grid--no-spacing mdl-shadow--2dp test-class';

    var inner_div_html = '\
    <div class="mdl-card mdl-cell mdl-cell--9-col-desktop mdl-cell--6-col-tablet mdl-cell--4-col-phone">\
    <div class="mdl-card__supporting-text">\
    <h6>Per test defaults</h6>\
    <label class="mdl-switch mdl-js-switch mdl-js-ripple-effect" for="save_har">\
      <input type="checkbox" id="save_har" class="mdl-switch__input" checked />\
      <span class="mdl-switch__label">save HAR file</span>\
    </label>\
    <label class="mdl-switch mdl-js-switch mdl-js-ripple-effect" for="save_pcap">\
      <input type="checkbox" id="save_pcap" class="mdl-switch__input" checked />\
      <span class="mdl-switch__label">save tcpdump file</span>\
    </label>\
    <label class="mdl-switch mdl-js-switch mdl-js-ripple-effect" for="save_screenshot ">\
      <input type="checkbox" id="save_screenshot " class="mdl-switch__input" checked />\
      <span class="mdl-switch__label">save screenshot when page is loaded</span>\
    </label>\
    </div>\
    <div class="mdl-card__actions">\
    <a href="#" onclick="append_test()" class="mdl-button">Create one</a>\
    </div>\
    </div>';
    var inner_div = $('<div/>').html(inner_div_html).contents();
    componentHandler.upgradeDom(inner_div, "mdl-card mdl-cell mdl-cell--9-col-desktop mdl-cell--6-col-tablet mdl-cell--4-col-phone");
    inner_div.appendTo(test_section);
    componentHandler.upgradeDom(test_section, 'section--center mdl-grid mdl-grid--no-spacing mdl-shadow--2dp');
    $('#config-from').append(test_section).show();
}
