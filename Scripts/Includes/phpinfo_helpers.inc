// various functions for auditing phpinfo output
//--------------------------------------------------------------------------------------------------------
function alertPhpInfo(phpInfoURI, http, vxml, details)
{	
	var ri = new TReportItem();
	ri.LoadFromFile(vxml);
	ri.affects = phpInfoURI;
	ri.alertPath = "Scripts/" + vxml;	
	
	ri.Details =  "This vulnerability was detected using the information from phpinfo() page [dark]" + phpInfoURI + "[/dark]";
	
	if (details) 
		ri.Details =  ri.Details + "[break]" + details;		
			
	ri.setHttpInfo(http);
	AddReportItem(ri);	
}
//--------------------------------------------------------------------------------------------------------
function checkForMySQLAuthBypass(phpInfoURI, http){    
    var match = http.response.body.match(/<td class="e">Client API version <\/td><td class="v">([^<]+)<\/td>/);
    if (match && match[1]) { 
        version = match[1].replace(/^\s+|\s+$/g, '');
        if (version.match(/^5.(0\..*|1\.([0-5]\d?|6[0-1])|2\.([0]\d?|1[0-1])|3\.([0-5])|5\.([0-1]\d?|2[0-2]))$/)) 
            alertPhpInfo(phpInfoURI, http, 'MYSQL_Auth_Bypass_CVE-2012-2122.xml', 'MySQL version: [dark][bold]' + version + '[/bold][/dark]');
    }
}
//--------------------------------------------------------------------------------------------------------
function checkForPHPConfigProblems(phpInfoURI, http){    
    var body = http.response.body;
    // allow_url_fopen
    var match = body.match(/<td class="e">allow_url_fopen<\/td><td class="v">On<\/td>/);
    if (match) { 
            alertPhpInfo(phpInfoURI, http, "phpinfo_allow_url_fopen.xml", 'allow_url_fopen: [dark][bold]On[/bold][/dark]');
    }
    
    // register_globals
    var match = body.match(/<td class="e">register_globals<\/td><td class="v">On<\/td>/);
    if (match) { 
            alertPhpInfo(phpInfoURI, http, 'phpinfo_register_globals.xml', 'register_globals: [dark][bold]On[/bold][/dark]');
    }
    
    // allow_url_include
    var match = body.match(/<td class="e">allow_url_include<\/td><td class="v">On<\/td>/);
    if (match) { 
            alertPhpInfo(phpInfoURI, http, 'phpinfo_allow_url_include.xml', 'allow_url_include: [dark][bold]On[/bold][/dark]');
    }    
    
    // session.use_trans_sid
    var match = body.match(/<td class="e">session.use_trans_sid<\/td><td class="v">1<\/td>/);
    if (match) { 
            alertPhpInfo(phpInfoURI, http, 'phpinfo_session_use_trans_sid.xml', 'session.use_trans_sid: [dark][bold]1[/bold][/dark]');
    }        
    
    // open_basedir
    var match = body.match(/<td class="e">open_basedir<\/td><td class="v"><i>no value<\/i><\/td>/);
    if (match) { 
            alertPhpInfo(phpInfoURI, http, 'phpinfo_open_basedir.xml', 'open_basedir: [dark][bold]no value[/bold][/dark]');
    }        
    
    // display_errors
    var match = body.match(/<td class="e">display_errors<\/td><td class="v">On<\/td>/);
    if (match) { 
            alertPhpInfo(phpInfoURI, http, 'phpinfo_display_errors.xml', 'display_errors: [dark][bold]On[/bold][/dark]');
    }   
    
    // session.use_only_cookies
    var match = body.match(/<td class="e">session\.use_only_cookies<\/td><td class="v">Off<\/td>/);
    if (match) { 
            alertPhpInfo(phpInfoURI, http, 'phpinfo_session_use_only_cookies.xml', 'session.use_only_cookies: [dark][bold]On[/bold][/dark]');
    }
}
//--------------------------------------------------------------------------------------------------------
function auditPHPInfoPage(phpInfoURI, http){
    checkForMySQLAuthBypass(phpInfoURI, http);
    // only run the following if Aspect is disabled.
    if (!http.hasAspectData) {
        checkForPHPConfigProblems(phpInfoURI, http);
    }
}