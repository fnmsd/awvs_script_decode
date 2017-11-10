#include helpers.inc;
{ 
	function classInjectionPatterns(){
		this.plainArray = [
						  ];
		this.regexArray = [
						  ];											
	}	    
    
	// *********************************************************************************************
	// ASP Code Injection class 
	// *********************************************************************************************	
	function classASPCodeInjection(targetUrl, injectionPatterns, scheme, inputIndex, variationIndex, reflectionPoint){
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
	}
	
	// *********************************************************************************************
	// function to make set a value for the current variation and issue an HTTP request 
	// *********************************************************************************************
	classASPCodeInjection.prototype.request = function(value)
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));
		this.scheme.setInputValue(this.inputIndex, value);
		
		this.lastJob = new THTTPJob();
		this.lastJob.url = this.targetUrl;		
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
	classASPCodeInjection.prototype.alert = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo, acuSensor)
	{	
		this.foundVulnOnVariation = true;
		var ri = new TReportItem();
		ri.LoadFromFile("ASP_Code_Injection.xml");
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/ASP Code Injection";
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
	classASPCodeInjection.prototype.testInjection = function(value, payload)
	{
		//trace("testInjection: " + value);
		if (!this.request(value)) return false;
		
		var job = this.lastJob;
		if(this.reflectionPoint) job = this.reflectionPoint;
		
		if (!this.reflectionPoint) {
			// AcuSensor is NOT enabled
			if (job.response.toString().indexOf(payload) != -1)		
			{
				this.alert(value, payload);
				return false;
			}
		}
        
		return true;
	}
	
	// *********************************************************************************************
	// main function to test all input variation
	// *********************************************************************************************	
	classASPCodeInjection.prototype.startTesting = function()
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
			if (this.injectionPatterns)				
			{	
                var num1 = 9000000+(Math.floor(Math.random()*1000000));
                var num2 = 9000000+(Math.floor(Math.random()*1000000));
                var num3 = num1*num2;
                
				// basic (no quotes)
				if (!this.testInjection("response.write(" + num1 + "*" + num2 + ")", num3)) continue;
				// basic (single quotes)
				if (!this.testInjection("'+response.write(" + num1 + "*" + num2 + ")+'", num3)) continue;
				// basic (double quotes)
				if (!this.testInjection("\"+response.write(" + num1 + "*" + num2 + ")+\"", num3)) continue;
			}			
		}
	}	
}