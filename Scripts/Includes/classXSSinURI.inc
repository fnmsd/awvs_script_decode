#include classXSS.inc;
var script_start_tag = "1<ScRiPt>";
var script_end_tag = "</ScRiPt>";
var documentType_invalid = -1;
var documentType_html = 1;
var documentType_xml = 2;
{ // class for testing XSS in URI
    function classXSSinURI(targetUrl, sf, separator){
		this.sf = sf;
		this.targetUrl = targetUrl;
        this.separator = separator;
		
		this.lastJob = null;
		this.found = new Object();
        
        this.foundXSS = false;
		
		this.classXSSInURI = true;
		this.shouldEncode = true;
        this.origValue = this.getOrigValue();
        this.origValueSep = ";";
	}
    
    // inheritance from classXSS
    classXSSinURI.prototype = classXSS.prototype;
    
    classXSSinURI.prototype.request = function(uri, dontEncode, testReflection)
	{	
		// if we should encode but we receive the request not to encode skip the test
		if (this.shouldEncode && dontEncode) return false;
		
		this.lastJob = new THTTPJob();
		this.lastJob.verb = 'GET';
		this.lastJob.url = this.targetUrl;
		
		var newUri = uri;
		
		var testUri = "";
		if (this.shouldEncode) testUri = plain2url(uri);
	    else testUri = uri.replace("\r", "%0D").replace("\n", "%0A").replace(" ", "+");
        
        var origURI = null;
        // for directory, we need to add / after the name
        if (this.sf.isDir) origURI = this.sf.path + this.sf.Name + "/";
		else origURI = this.sf.path + this.sf.Name;
		if (!testReflection) {
            newUri = origURI + this.separator + testUri;
		}
        // populate referer tag - some sites may need it
        if (!this.lastJob.request.headerExists('Referer'))
            this.lastJob.request.addHeader('Referer', scanURL.url, false);
		//trace(newUri);
		this.lastJob.autoRedirect = true;
		this.lastJob.uri = newUri;
		this.lastJob.execute();
		
		// block a redirect to another host
		if (!this.lastJob.wasError) {
			var host = this.lastJob.request.headerValue('Host');			
			if (host && host.toLowerCase() != scanURL.host.toLowerCase()) {
				//logError(host.toLowerCase());
				//logError(scanURL.host.toLowerCase());
				return false;
			}
		}
				
		return ((!this.lastJob.wasError || (this.lastJob.wasError && this.lastJob.errorCode == 0xF0003))); 
	}
	/**************************************************************************************************************/
	classXSSinURI.prototype.alert = function(uri)
	{	
		var ri = new TReportItem();
		ri.LoadFromFile("XSS.xml");
		
		ri.affects = this.sf.fullPath;
		ri.alertPath = "Scripts/XSS";
		ri.details = "URI was set to [bold][dark]" + uri + "[/dark][/bold]";
	
		var extraDetails = this.prepareDetailsString(uri);
		if (extraDetails) ri.details = ri.details + "[break]" + extraDetails;		
        
        if (this.isVerified(uri))
            ri.name = ri.name + " (verified)";
		
		ri.setHttpInfo(this.lastJob);		
		AddReportItem(ri);	
        
        this.foundXSS = true;
	}		
	
	/**************************************************************************************************************/
	classXSSinURI.prototype.alertHTMLInjection = function(uri)
	{	
        var vxml = 'HTML_Injection.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.sf.fullPath;
		ri.alertPath = "Scripts/" + vxml;
		ri.details = "URI was set to [bold][dark]" + uri + "[/dark][/bold]";
	
		var extraDetails = this.prepareDetailsString(uri);
		if (extraDetails) ri.details = ri.details + "[break]" + extraDetails;			
		
		if (extraDetails) {
			ri.details = ri.details + "[break]" + extraDetails;		
			if (extraDetails.indexOf("non-terminated parameter") != -1) {
				ri.name = "HTML injection with non-terminated parameter";
			}
		}
		
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);
	}
	
	/**************************************************************************************************************/
	classXSSinURI.prototype.testReflection = function()
	{	
		// test three types of reflection
		
		// %40 => @ URL encoded to check if the input should be URL encoded or not.
		
		// URI index.php/something		
		var rndStr = (900000 + random(99999)).toString();
		var uri = null;
		
		// for directory, we need to add / after the name
		if (this.sf.isDir) uri = this.sf.path + this.sf.Name + "/";
		else uri = this.sf.path + this.sf.Name;
		uri = uri + this.separator + rndStr + "%40";
		if (!this.request(uri, null, true)) return false;
		var m = /<!DOCTYPE HTML PUBLIC "-\/\/IETF\/\/DTD HTML 2.0\/\/EN">\n<html><head>\n<title>404 Not Found<\/title>\n<\/head><body>\n<h1>Not Found<\/h1>\n<p>The requested URL [^\s]* was not found on this server.<\/p>/.exec(this.lastJob.response.body);
		if (!m) {
            
            this.founds = new Array();
        
        	// get content-type
        	var ct = this.lastJob.response.headerValue('content-type').toLowerCase();
            
            // detect content type
        	if (ct == '' || ct.indexOf('html') != -1)         
                this.documentType = documentType_html; 
            else                 
            if (ct.indexOf('xml') != -1)             
                this.documentType = documentType_xml;             
            else this.documentType = documentType_invalid; 
                
            if (this.documentType != documentType_invalid)
    		    this.founds = SearchInputInResponse(rndStr, this.lastJob.response.body);
			
			if (this.founds.length > 0) {
				// check if we should encode the input or not
				if (this.lastJob.response.body.indexOf(rndStr + '@')!=-1) this.shouldEncode = true;
				else this.shouldEncode = false;		
				
				return true;
			}
		}       
		
		return false;
	}	
	
	/**************************************************************************************************************/
	/*	here are the tests 																						  */	
	/**************************************************************************************************************/
		
	/**************************************************************************************************************/
	classXSSinURI.prototype.testRubyOnRailsVuln = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 900000 + random(99999);			
		var inputValue = script_start_tag + "prompt(" + rndStr + ")" + script_end_tag + "=\xA2";
		if (!this.request(inputValue)) return false;
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=prompt(" + rndStr + ")")) {			
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
	
	/**************************************************************************************************************/
	classXSSinURI.prototype.startTesting = function()
	{
		if (!this.testReflection()) return;			
		// start making tests
        this.makeTests();
	}	
}