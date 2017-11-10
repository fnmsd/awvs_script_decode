var lastJob = null;
var testedFileName = "";
var phpPattern = /(\<\?(php|\s+)[\x20-\x80\x0d\x0a\x09]+)/i;
var lastMatch = "";
// **************************************************************************************							 
function alertWebAppConfigBackupFile()
{	
	var ri = new TReportItem();
    var fname = "webapp_config_file_disclosure.xml";
	ri.LoadFromFile(fname);
	ri.affects = lastJob.URI;
	ri.alertPath = "Scripts/" + fname;	
    ri.details = "Configuration file variant found: [dark][bold]" + testedFileName + "[/bold][/dark][break][break]";
    ri.details = ri.details + "[pre]" + lastMatch[0] + "[/pre]";    
	
	ri.setHttpInfo(lastJob);	
	AddReportItem(ri);	
}
// **************************************************************************************
function lookForConfigFileBackup(dir, path, fileName, fileExt, variant) {
    var res = "";
	var fname = variant.replace("${fileName}", fileName);
	if (fileExt != "") fname = fname.replace("${fileExt}", "." + fileExt);
	
	testedFileName = fname;
	
	var uri = path + "/" + plain2url(fname);
    //trace(uri);
	var http = new THTTPJob();
    lastJob  = http;
	
	http.url = dir.url;
	http.verb = 'GET';
	http.URI = uri;
	http.execute();	
	
	if (!http.wasError && !http.notFound){
        lastMatch = phpPattern.exec(http.response.body);
        if (lastMatch) {
            // set return value
            res = uri;
		    // add link to crawler
		    addLinkToCrawler(uri, dir);            
        }
	}
    
    return res;
}
// **************************************************************************************
function testConfigFileBackupFile(dir, path, fileName, fileExt){
    // first, test for false-positives    
    if (lookForConfigFileBackup(dir, path, '~' + randStr(8), 'php', '${fileName}${fileExt}~')) return false;
    
    // test it with all backup variants	until we got a hit
    for (var i=0; i<variants.length; i++) 
    {
    	var uri = lookForConfigFileBackup(dir, path, fileName, fileExt, variants[i], variants[i])
        if (uri) {
            alertWebAppConfigBackupFile();  
            break;
        }
    }    
}
