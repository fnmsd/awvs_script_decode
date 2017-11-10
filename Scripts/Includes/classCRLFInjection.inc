#include helpers.inc;
#include os_detection.inc;
#include error_messages_helpers.inc;
var debug = false;
{
	// *********************************************************************************************
	// class for testing the signs of an injection using text patterns found in the response text
	// *********************************************************************************************	
	function classInjectionPatterns(){
		this.plainArray = [
						  ];
		this.regexArray = [
							/[\n|\r](SomeCustomInjectedHeader\s*:\s*injected_by_wvs)/
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
	// CRLF Injection class 
	// *********************************************************************************************	
	function classCRLFInjection(targetUrl, injectionPatterns, scheme, inputIndex, variationIndex, reflectionPoint){
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
	
	// *********************************************************************************************
	// function to detect if AcuSensor data indicates an CRLF Injection vulnerability
	// params:  
	//	ad => AspectData object
	// returns: 
	//	an AspectDataItem if true / False
	// *********************************************************************************************
	classCRLFInjection.prototype.isCRLF = function(ad) {			
		var adItems = ad.getItemsWithKey("Set_Header");
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
					if (item.indexOf(this.injectionValidator.startMark + "\r\n" + this.injectionValidator.endMark) != -1) 
						return new InjectionResult(item, aditem);
				}				
			} 		
		}
		
		return false;
	}	
	
	// *********************************************************************************************
	// function to make set a value for the current variation and issue an HTTP request 
	// *********************************************************************************************
	classCRLFInjection.prototype.request = function(value, dontEncode)
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));
        if (dontEncode) this.scheme.setEncodedInputValue(this.inputIndex, value);
        else this.scheme.setInputValue(this.inputIndex, value);
		
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
	classCRLFInjection.prototype.alert = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo, acuSensor)
	{	
		this.foundVulnOnVariation = true;
		
		var ri = new TReportItem();
		ri.LoadFromFile("CRLF_Injection.xml");
		if (acuSensor) ri.name = ri.name + " (verified)";
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/CRLF Injection";
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.sensorSourceFile = sourceFile;
		ri.sensorSourceLine = sourceLine;
		ri.sensorAdditional = additionalInfo;			
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		if (matchedText) 
			ri.Details =  ri.Details + "[break]Injected header found: [pre][blue]" + matchedText + "[/blue][/pre]";
		
		ri.setHttpInfo(this.lastJob);
		AddReportItem(ri);	
	}
    // *********************************************************************************************
    // test reflection
    // *********************************************************************************************
    classCRLFInjection.prototype.testReflection = function()
    {
        if (debug) trace("testReflection");
        var token = randStr(8);
        if (!this.request(token)) return false;
        return (this.lastJob.response.headersString.indexOf(token) != -1);
    }
	// *********************************************************************************************
	// test injection 
	// *********************************************************************************************	
	classCRLFInjection.prototype.testInjection = function(value, dontEncode)
	{
        if (debug) trace("testInjection: " + value);
		if (!this.request(value, dontEncode)) return false;
		
		var job = this.lastJob;
		if(this.reflectionPoint) job = this.reflectionPoint;
		
		// if AcuSensor is enabled
		if (job.hasAspectData) {
			// get aspect data information
			var ad = job.getAspectData();
			var injRes = this.isCRLF(ad);
			
			if (injRes && injRes.adItem) {				
				this.alert(value, "", injRes.adItem.FileName, injRes.adItem.lineNumber, "", 1);
				return false;
			}
		}		
		
		else 
		{
			if (!this.reflectionPoint) {
				// AcuSensor is NOT enabled
				var matchedText = this.injectionPatterns.searchOnText(job.response.headersString);		
				if (matchedText) {
					this.alert(value, matchedText);
					return false;
			 	}			 	
			} 	
		}
		
		return true;
	}
	
	// *********************************************************************************************
	// main function to test all input variation
	// *********************************************************************************************	
	classCRLFInjection.prototype.startTesting = function()
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
			if (this.scheme.targetHasAcuSensor) 
			{	
				this.injectionValidator.startMark = ACUINJSTART;
				this.injectionValidator.endMark = ACUINJEND;
				
				// basic
				if (!this.testInjection("ACUSTART\r\nACUEND")) continue;
				
			}
			else
			// AcuSensor is NOT enabled				
			{
                // reflection
                if (this.testReflection()) {
                    // \r\n
                    if (!this.testInjection("\r\nSomeCustomInjectedHeader: injected_by_wvs")) continue;
                    // \r\n\t
                    if (!this.testInjection("\r\n\tSomeCustomInjectedHeader: injected_by_wvs")) continue;
                    // \r\n\s
                    if (!this.testInjection("\r\n SomeCustomInjectedHeader: injected_by_wvs")) continue;
                    // \r\t
                    if (!this.testInjection("\r\tSomeCustomInjectedHeader: injected_by_wvs")) continue;
                    // \n
                    if (!this.testInjection("\nSomeCustomInjectedHeader: injected_by_wvs")) continue;
                    // \r
                    if (!this.testInjection("\rSomeCustomInjectedHeader: injected_by_wvs")) continue;
                    // twitter crlf
                    if (!this.testInjection("%E5%98%8A%E5%98%8DSomeCustomInjectedHeader:%20injected_by_wvs", true)) continue;
					// node js crfl
					if (!this.testInjection("%c4%8d%c4%8aSomeCustomInjectedHeader:%20injected_by_wvs", true)) continue;
                }
			}
		}	
	}	
}