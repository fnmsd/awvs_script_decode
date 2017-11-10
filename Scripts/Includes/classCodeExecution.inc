#include helpers.inc;
#include string_helpers.inc;
#include error_messages_helpers.inc;
{
	// *********************************************************************************************
	// class for testing the signs of an injection using text patterns found in the response text
	// *********************************************************************************************	
	function classInjectionPatterns(){
		this.plainArray = [
						  ];
		this.regexArray =
                        [
                            /(Path=[\s\S]*?PWD=)/i,
                            /(Path=[\s\S]*?PATHEXT=)/i,
                            /(Path=[\s\S]*?SHELL=)/i,
                            /(Path\\x3d[\s\S]*?PWD\\x3d)/i,			// json encoded "=" => "\x3d"
                            /(Path\\x3d[\s\S]*?PATHEXT\\x3d)/i,		// json encoded
                            /(Path\\x3d[\s\S]*?SHELL\\x3d)/i,		// json encoded
                            /SERVER_SIGNATURE=[\s\S]*?SERVER_SOFTWARE=/,
                            /SERVER_SIGNATURE\\x3d[\s\S]*?SERVER_SOFTWARE\\x3d/,
                            /(Non-authoritative\sanswer:\s+Name:\s*)/i,
                            /(Server:\s*.*?\nAddress:\s*)/i
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
	// Code Execution class 
	// *********************************************************************************************	
	function classCodeExecution(targetUrl, injectionPatterns, scheme, inputIndex, variationIndex, reflectionPoint){
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
        this.lastJobVerify = null;
		this.injectionValidator = new TInjectionValidator(ACUINJSTART, ACUINJEND);		
	}
	
	// *********************************************************************************************
	// function to detect if AcuSensor data indicates an Code Execution vulnerability
	// params:  
	//	ad => AspectData object
	// returns: 
	//	an AspectDataItem if true / False
	// *********************************************************************************************
	classCodeExecution.prototype.isCodeExecution = function(ad) {			
		var adItems = ad.getItemsWithKey("Sys_Command");
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
					if (item.indexOf(this.injectionValidator.startMark) != -1) 
					{
						if (this.injectionValidator.isShellCodeInjection(item))
							return new InjectionResult(item, aditem);						
					}					
				}				
			} 		
		}
		
		return false;		
	}	
	
	// *********************************************************************************************
	// function to make set a value for the current variation and issue an HTTP request 
	// *********************************************************************************************
	classCodeExecution.prototype.request = function(value)
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));
		
		// for files manipulate also the input filename and set a valid content-type
		if (this.scheme.hasFileInput && (this.scheme.getInputFlags(this.inputIndex) & INPUT_FLAG_IS_FILE)){
			this.scheme.setInputFileName(this.inputIndex, value);
			this.scheme.setInputContentType(this.inputIndex, "image/png");
			this.scheme.setInputValue(this.inputIndex, value);
		}
		else this.scheme.setInputValue(this.inputIndex, value);
		
		this.lastJob = new THTTPJob();
		this.lastJob.url = this.targetUrl;		
		if (this.scheme.targetHasAcuSensor) this.lastJob.addAspectHeaders();		
		this.scheme.populateRequest(this.lastJob);
 
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
    classCodeExecution.prototype.requestVerify = function(value)
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));
		this.scheme.setInputValue(this.inputIndex, value);
		
		this.lastJobVerify = new THTTPJob();
		this.lastJobVerify.url = this.targetUrl;		
		this.scheme.populateRequest(this.lastJobVerify);
 
		this.lastJobVerify.execute();
		return ((!this.lastJobVerify.wasError || (this.lastJobVerify.wasError && this.lastJobVerify.errorCode == 0xF0003))); 
	}	
	// *********************************************************************************************
	// generates an report item for the scanner
	// *********************************************************************************************
	classCodeExecution.prototype.alert = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo, acuSensor)
	{	
		this.foundVulnOnVariation = true;
		
		var ri = new TReportItem();
		ri.LoadFromFile("Code_Execution.xml");
		if (acuSensor) ri.name = ri.name + " (verified)";
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/Code Execution";
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.sensorSourceFile = sourceFile;
		ri.sensorSourceLine = sourceLine;
		ri.sensorAdditional = additionalInfo;			
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		if (matchedText) 
			ri.Details =  ri.Details + "[break]Possible execution result: [pre][blue]" + matchedText + "[/blue][/pre]";
		
		if (this.reflectionPoint) {
			ri.name = ri.name + ' [Stored]';
			ri.details = ri.details + "[break]The input is reflected in [bold][dark]" + this.reflectionPoint.url.url + "[/dark][/bold]";
		}
				
		ri.setHttpInfo(this.lastJob);					
				
		AddReportItem(ri);	
	}		
	// *********************************************************************************************
	// test injection 
	// *********************************************************************************************	
	classCodeExecution.prototype.testInjection = function(value, userData)
	{
        var domain = randStr(8);
        if(typeof userData !== 'undefined' && bxss_enabled == 1 && bxss_userId && bxss_url){
            var reqId = saveTest(this.inputIndex, this.variations.item(this.currentVariation), userData);
            if (reqId) {
                var reqIdParts = reqId.split("-");
                var reqScanId = reqIdParts[0];
                var reqHash = plain2md5(this.scheme.path + this.scheme.hash + reqScanId).substring(1,6);
                domain = "dns.ce.\\" + bxss_userId + "." + reqId + "." + reqScanId + "." + reqHash + ".\\1.bxss.me";
            }
        }
        value = value.replaceAll("{domain}", domain);
		//trace("testInjection: " + value);
		if (!this.request(value)) return false;
		
		var job = this.lastJob;
		if(this.reflectionPoint) job = this.reflectionPoint;
		
		// if AcuSensor is enabled
		if (job.hasAspectData) {
			// get aspect data information
			var ad = job.getAspectData();
			var injRes = this.isCodeExecution(ad);
			
			if (injRes && injRes.adItem) {				
				var additional = "Command: " + injRes.data + "\r\n" + injRes.adItem.additional;
				this.alert(value, "", injRes.adItem.FileName, injRes.adItem.lineNumber, additional, 1);
				return false;
			}
			
		}		
		
		else {
			if (!this.reflectionPoint) {
				// AcuSensor is NOT enabled
				var matchedText = this.injectionPatterns.searchOnText(job.response.body);
				if (matchedText)
                {
                    // nslookup domain
                    if (job.response.body.indexOf(domain) != -1) {
                        // verify the alert
                        var rndStr = 900000 + random(99999);
                        if (!this.requestVerify(rndStr)) return false;
                        var verifyText = this.injectionPatterns.searchOnText(this.lastJobVerify.response.body);
                        if (!verifyText)
                        {
                            this.alert(value, matchedText);
                            return false;
                        }
                    }
                    // no domain was used
                    else
                    {
                        // verify the alert
                        var rndStr = 900000 + random(99999);
                        if (!this.requestVerify(rndStr)) return false;
                        var verifyText = this.injectionPatterns.searchOnText(this.lastJobVerify.response.body);
                        if (!verifyText)
                        {
                            this.alert(value, matchedText);
                            return false;
                        }
                    }
				}
			}
		}
		
		return true;
	}
	
	// *********************************************************************************************
	// main function to test all input variation
	// *********************************************************************************************	
	classCodeExecution.prototype.startTesting = function()
	{
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
					if (!this.testInjection("ACUSTART'\"^|;<>ACUEND")) continue;
				}
				
				else { 
					// have reflection point
					this.injectionValidator.startMark = "ASbegin";
					this.injectionValidator.endMark = "ASend";
				
					// basic
					if (!this.testInjection("ASbegin'\"^|;<>ASend")) continue;
				}
			}
			else 
			// AcuSensor is NOT enabled				
			if (this.injectionPatterns)				
			{
					// the tests (generic)
                    // classic test
                    if (!this.testInjection("set|set&set")) continue;
                    // $(cmd)
                    if (!this.testInjection("$(nslookup {domain})", 37)) continue;
                    // Combined
                    if (!this.testInjection('&nslookup {domain}&\'\\"`0&nslookup {domain}&`\'', 38)) continue;
                    //if (!this.testInjection("nslookup {domain}|nslookup {domain}&nslookup {domain}", 30)) continue;
					//if (!this.testInjection("'nslookup {domain}|nslookup {domain}&nslookup {domain}'", 31)) continue;
					//if (!this.testInjection('"nslookup {domain}|nslookup {domain}&nslookup {domain}"', 32)) continue;
                    // print
                    // if (!this.testInjection("print `nslookup {domain}`", 35)) continue;
                    // comma
					// this.testInjection(";nslookup {domain}|nslookup {domain}&nslookup {domain};", 36);
			}
		}
    }
}