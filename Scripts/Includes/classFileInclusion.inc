#include helpers.inc;
#include error_messages_helpers.inc;
{
	// *********************************************************************************************
	// class for testing the signs of an injection using text patterns found in the response text
	// *********************************************************************************************	
	function classInjectionPatterns(){
		this.plainArray = [
							'63c19a6da79816b21429e5bb262daed863c19a6da79816b21429e5bb262daed8',
            				'java.lang.IllegalArgumentException: URI can\'t be null.',
                            '<td align="right" valign="middle" bgcolor="#008F00" class="disclaimer">TEST and Demonstration site for Acunetix Web Vulnerability Scanner</td>'
						  ];
		this.regexArray = [
							/(<b>Fatal error<\/b>:.*: Failed opening required '.*acunetix.*').*/,
                            /Failed opening required\s'.*?some_inexistent_file_with_long_name.*?'\s/,
                            /Warning: fopen\(.*?some_inexistent_file_with_long_name.*?\)\s/,
							/(<b>Warning<\/b>:.*: Failed opening '.*some_inexistent_file_with_long_name.*') for inclusion.*/,
							/\[FileNotFoundException:\sCould\snot\sfind\sfile\s'.*some_inexistent_file_with_long_name.*'.\]/,
							/java.io.FileNotFoundException:\s.*?\shttp:\/\/some-inexistent-website.acu\/some_inexistent_file_with_long_name.*/,
							/java\.net\.MalformedURLException:\sno protocol:\s1some_inexistent_file_with_long_name/,
							/java\.lang\.IllegalArgumentException:\sURI has an authority component/,
							/(org.apache.jasper.JasperException: .*? File .*? not found)/,
							/(Failed opening '.*some_inexistent_file_with_long_name.*' for inclusion)/,
							/(<b>(Warning|Fatal\serror)<\/b>:(?:(?:\s*?main\(\))|(?:\s*?(include|include_once|require|require_once)\(\) \[<a href='function.(include|require)'>function.(include|require)<\/a>\])): Failed opening (required\s)?'.*some_inexistent_file_with_long_name.*')/,
							/(java\.io\.FileNotFoundException:\s.*?:\/testasp.vulnweb.com\/t\/fit.txt\s)/,
							/(java.io.FileNotFoundException:\shttps?:\/\/.*?\/testasp.vulnweb.com)[\s\n]/,
							/(java.io.FileNotFoundException:\/testasp.vulnweb.com\/t\/fit.txt)[\s\n]/,
							/(<b>Warning<\/b>:  (file_get_contents\(.*some_inexistent_file_with_long_name.*\)( \[<a href='function.file-get-contents'>function.file-get-contents<\/a>\])?|fopen\(.*some_inexistent_file_with_long_name.*\)( \[<a href='function.fopen'>function.fopen<\/a>\])?): failed to open stream: (No such file or directory|Invalid argument|(HTTP request failed! .*)) in <b>.*?<\/b> on line <b>.*?<\/b>)/
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
	// File Inclusion class 
	// *********************************************************************************************	
	function classFileInclusion(targetUrl, injectionPatterns, scheme, inputIndex, variationIndex, reflectionPoint){
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
	
    classFileInclusion.prototype.getOrigValue = function()
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
	// function to detect if AcuSensor data indicates an File Inclusion vulnerability
	// params:  
	//	ad => AspectData object
	// returns: 
	//	an AspectDataItem if true / False
	// *********************************************************************************************
	classFileInclusion.prototype.isFileInclusion = function(ad) {	
        if (ad == null) return false;		
		var adItems = ad.getItemsWithKey("PHP_File_Include");
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
						if (this.injectionValidator.isPathInjection(item))
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
	classFileInclusion.prototype.request = function(value, dontEncode)
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
	classFileInclusion.prototype.alert = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo, acuSensor)
	{	
		this.foundVulnOnVariation = true;
		var ri = new TReportItem();
		ri.LoadFromFile("File_inclusion.xml");
		if (acuSensor) ri.name = ri.name + " (verified)";
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/File Inclusion";
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;
		ri.sensorSourceFile = sourceFile;
		ri.sensorSourceLine = sourceLine;
		ri.sensorAdditional = additionalInfo;			
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		if (matchedText) 
			ri.Details =  ri.Details + "[break]Pattern found: [pre][blue]" + matchedText + "[/blue][/pre]";
		
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
	classFileInclusion.prototype.testInjection = function(value, dontEncode)
	{
		//trace("testInjection: " + value);
		if (!this.request(value, dontEncode)) return false;
		
		var job = this.lastJob;
		if(this.reflectionPoint) job = this.reflectionPoint;
		
		// if AcuSensor is enabled
		if (job.hasAspectData) {
			// get aspect data information
			var ad = job.getAspectData();
			var injRes = this.isFileInclusion(ad);
			
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
					this.alert(value, matchedText);
					return false;
				}
			}
		}
		
		return true;
	}
	
	// *********************************************************************************************
	// test injection 
	// *********************************************************************************************	
	classFileInclusion.prototype.testInjectionSelfInclude = function(value)
	{
		//trace("testInjectionSelfInclude: " + value);
		if (!this.request(value, 0)) return false;
		var job = this.lastJob;
		
		var match = job.response.toString().match(/(<%@[^%]+?%>)/);
		if (match && match[1]) { 		
			this.alert(value, match[1]);
			return false;
		}
		
		return true;
	}	
	// *********************************************************************************************
	// main function to test all input variation
	// *********************************************************************************************	
	classFileInclusion.prototype.startTesting = function()
	{
		// don't test on Host header
        var inputType = this.scheme.getInputTypeStr(this.inputIndex);
        var inputName = this.scheme.getInputName(this.inputIndex);
        
        //LogError(scheme.path + " " + inputType + "/" + inputName);
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
					if (!this.testInjection("1ACUSTARTFILE/../../xxx\\..\\..\\ACUENDFILE", 0)) continue;
					// Absolute Unix
					if (!this.testInjection("1/ACUSTARTFILE/ACUENDFILE", 0)) continue;
					// Absolute Windows
					if (!this.testInjection("1\\ACUSTARTFILE\\ACUENDFILE", 0)) continue;
				}
				
				else { 
					// have reflection point
					this.injectionValidator.startMark = "ASbegin";
					this.injectionValidator.endMark = "ASend";
				
					// basic
					if (!this.testInjection("1ASbegin/../../xxx\\..\\..\\ASend", 0)) continue;
					// Absolute Unix
					if (!this.testInjection("1/ASbegin/ASend", 0)) continue;
					// Absolute Windows
					if (!this.testInjection("1\\ASbegin\\ASend", 0)) continue;				
				}
			}
			else
				
			// AcuSensor is NOT enabled		 
			if (this.injectionPatterns)				
			{		
                var origValue = this.getOrigValue();
                var extension = "jpg";
                if (origValue && origValue.indexOf(".") != -1) extension = origValue.split('.').pop();
				// determine the extension for the current scheme to make some Java specific tests
				var schemeExtension = "";
				var schemePath = scheme.path;
				if (schemePath && schemePath.indexOf(".") != -1) {
					schemeExtension = schemePath.split('.').pop();
					schemeFileName = schemePath.split('/').pop();
				}
				
				// external web site
				if (!this.testInjection("http://some-inexistent-website.acu/some_inexistent_file_with_long_name%3F." + extension, 1)) continue;					
				// local file
				if (!this.testInjection("1some_inexistent_file_with_long_name%00." + extension, 1)) continue;
				// Acunetix test (without extension)
				if (!this.testInjection("Http://testasp.vulnweb.com/t/fit.txt", 1)) continue;
				// Acunetix test (with origvalue extension)
				if (!this.testInjection("http://testasp.vulnweb.com/t/fit.txt%3F." + extension, 1)) continue;
                // simple domain
				if (!this.testInjection("testasp.vulnweb.com", 0)) continue;				
				
				// for jsp that have a default value that looks like a file, try to read the current file
				if (schemeExtension == 'jsp' && origValue.indexOf("/") != -1) {
					if (!this.testInjectionSelfInclude(schemePath)) continue;
					if (!this.testInjectionSelfInclude(schemePath.replace(/^\/[^\/]+/, ""))) continue;
					if (!this.testInjectionSelfInclude(schemePath.replace(/^\/[^\/]+/, "").replace(/^\/[^\/]+/, ""))) continue;
					if (!this.testInjectionSelfInclude(schemePath.replace(/^\/[^\/]+/, "").replace(/^\/[^\/]+/, "").replace(/^\/[^\/]+/, ""))) continue;
				}
				// for jsp also try to include the current filename
				if (schemeExtension == 'jsp') {
					if (!this.testInjectionSelfInclude(schemeFileName)) continue;
					if (!this.testInjectionSelfInclude("./" + schemeFileName)) continue;
                    if (!this.testInjectionSelfInclude("/" + schemeFileName)) continue;
				}
			}
		}
	}	
}