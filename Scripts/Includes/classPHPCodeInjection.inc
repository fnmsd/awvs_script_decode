#include helpers.inc;
{
	// *********************************************************************************************
	// class for testing the signs of an injection using text patterns found in the response text
	// *********************************************************************************************	
	function classInjectionPatterns(){
		this.plainArray = [
							"63c19a6da79816b21429e5bb262daed8"
						  ];
		this.regexArray = [
                            /Parse error: syntax error,.*?\sin\s.*?\(\d+\).*?eval\(\)\'d\scode\son\sline\s<i>\d+<\/i>/
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
	// PHP Code Injection class 
	// *********************************************************************************************	
	function classPHPCodeInjection(targetUrl, injectionPatterns, scheme, inputIndex, variationIndex, reflectionPoint){
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
	// function to detect if AcuSensor data indicates an PHP Code Injection vulnerability
	// params:  
	//	ad => AspectData object
	// returns: 
	//	an AspectDataItem if true / False
	// *********************************************************************************************
	classPHPCodeInjection.prototype.isPHPCodeInjection = function(ad) {			
		var adItems = ad.getItemsWithKey("PHP_Code_Eval");
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
					//trace(item);
					if (item.indexOf(this.injectionValidator.startMark) != -1) 
					{
						if (this.injectionValidator.isPHPCodeInjection(item))
							return new InjectionResult(item, aditem);						
					}					
				}				
			} 		
		}
		
		return false;		
	}	
	
	// *********************************************************************************************
	// function to detect if AcuSensor data indicates an PHP Code Injection vulnerability
	// params:  
	//	ad => AspectData object
	// returns: 
	//	an AspectDataItem if true / False
	// *********************************************************************************************
	classPHPCodeInjection.prototype.isPHPCodeInjectionWarning = function(ad) {			
		var adItems = ad.getItemsWithKey("PHP_Code_Eval");
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
					//trace(item);
					if (item.indexOf(this.injectionValidator.startMark) != -1) 
					{
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
	classPHPCodeInjection.prototype.request = function(value)
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
	// generates an report item for the scanner
	// *********************************************************************************************
	classPHPCodeInjection.prototype.alert = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo, acuSensor)
	{	
		this.foundVulnOnVariation = true;
		
		var ri = new TReportItem();
		ri.LoadFromFile("PHP_Code_Injection.xml");
		if (acuSensor) ri.name = ri.name + " (verified)";
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/PHP Code Injection";
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
	// generates an report item for the scanner
	// *********************************************************************************************
	classPHPCodeInjection.prototype.alert_warning = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo)
	{	
		var ri = new TReportItem();
		ri.LoadFromFile("PHP_eval_used_on_user_input.xml");
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/PHP eval() used on user input";
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.sensorSourceFile = sourceFile;
		ri.sensorSourceLine = sourceLine;
		ri.sensorAdditional = additionalInfo;			
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		
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
	classPHPCodeInjection.prototype.testInjection = function(value)
	{
		// trace("testInjection: " + value);
		if (!this.request(value)) return false;
		
		var job = this.lastJob;
		if(this.reflectionPoint) job = this.reflectionPoint;
		
		// if AcuSensor is enabled
		if (job.hasAspectData) {
			
			// let's do a text search just in case			
			var matchedText = this.injectionPatterns.searchOnText(job.response.toString());		
			if (matchedText) 
			{
				this.alert(value, matchedText);
				return false;
			}			
			
			// get aspect data information
			var ad = job.getAspectData();
			
			// check for PHP code injection
			var injRes = this.isPHPCodeInjection(ad);
			
			if (injRes && injRes.adItem) {				
				var additional = "Command: " + injRes.data + "\r\n" + injRes.adItem.additional;
				this.alert(value, "", injRes.adItem.FileName, injRes.adItem.lineNumber, additional, 1);
				return false;
			}
			
			// check for PHP code injection warning
			var injRes = this.isPHPCodeInjectionWarning(ad);
			
			if (injRes && injRes.adItem) {				
				var additional = "Command: " + injRes.data + "\r\n" + injRes.adItem.additional;
				this.alert_warning(value, "", injRes.adItem.FileName, injRes.adItem.lineNumber, additional);
				return true;
			}			
		}		
		
		else {
			if (!this.reflectionPoint) {
				// AcuSensor is NOT enabled
				var matchedText = this.injectionPatterns.searchOnText(job.response.toString());		
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
	classPHPCodeInjection.prototype.startTesting = function()
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
				if (!this.reflectionPoint) 
				{ 
					// NO reflection point
					this.injectionValidator.startMark = ACUINJSTART;
					this.injectionValidator.endMark = ACUINJEND;
					
					// basic
					if (!this.testInjection("1ACUSTART'\"*/\x0d\x0a\x20\x3C\x3FphpACUEND")) continue;
					// test for reflection
					if (!this.testInjection("1ACUSTART")) continue;
					// no quoting
					if (!this.testInjection("${@print(md5(acunetix_wvs_security_test))}")) continue;
					// quoting
					if (!this.testInjection("${@print(md5(acunetix_wvs_security_test))}\\")) continue;					
				}
				else 
					
				{
					// have reflection point
					this.injectionValidator.startMark = "ASbegin";
					this.injectionValidator.endMark = "ASend";					
					// basic
					if (!this.testInjection("1ASbegin'\"*/\x0d\x0a\x20\x3C\x3FphpASend")) continue;
				}
			}
			else 
			// AcuSensor is NOT enabled				
			if (this.injectionPatterns)				
			{	
				// basic (between ;)
				if (!this.testInjection(";print(md5(acunetix_wvs_security_test));")) continue;
				// basic (between ; and single quotes)
				if (!this.testInjection("';print(md5(acunetix_wvs_security_test));$a='")) continue;
				// basic (between ; and double quotes)
				if (!this.testInjection("\";print(md5(acunetix_wvs_security_test));$a=\"")) continue;
				// no quoting
				if (!this.testInjection("${@print(md5(acunetix_wvs_security_test))}")) continue;
				// quoting
				if (!this.testInjection("${@print(md5(acunetix_wvs_security_test))}\\")) continue;
			}		
				
		}
	}	
}