#include email_storage.inc;
#include error_messages_helpers.inc;
{
	function classMatches()
	{
		this.plainArray = [];
		this.regexArray = [];							
	}
	
	classMatches.prototype.searchOnText = function(text, matchIndex) 
	{
		// search plain texts first
		for (var i=0;i<this.plainArray.length;i++) 
		{
			if (text.indexOf(this.plainArray[i]) != -1) 
				return this.plainArray[i];
		}
			
		// search regexes
		for (var i=0;i<this.regexArray.length;i++) 
		{
			var m = this.regexArray[i].exec(text);            
			if (m) {
                if (matchIndex>0) return m[matchIndex]
                else return m[0]
            }
		}						
		return false;	
	}
    /*************************************************************************************************************************/
    function eliminateInvalidEmails(arr) {
        result = [];
        for (var i=0;i<arr.length;i++) {
            if (validEmail(arr[i]))
            result.push(arr[i]);
        }
        return result;
    }
	
	classMatches.prototype.searchEmailsOnText = function(text) {
		// search plain texts first
		for (var i=0;i<this.plainArray.length;i++) {
			if (text.indexOf(this.plainArray[i]) != -1) return this.plainArray[i];
		}
			
		// search regexes
		for (var i=0;i<this.regexArray.length;i++) {            
            var emails = new Array();			
			while (m = this.regexArray[i].exec(text))
			{
                emails.push(m[0]);
			}
            
            var noDuplicates = eliminateInvalidEmails(eliminateDuplicates(emails));
            var res = "";
            for (var j=0;j<noDuplicates.length;j++) {
                res = res + noDuplicates[j] + "\r\n";				    
            }            
			
			if (res != "") 	return res;			
		}		
        
		return false;	
	}	
    
	classMatches.prototype.searchObfuscatedEmailsOnText = function(text) {
		// search extra regexes
		for (var i=0;i<this.extraRegexArray.length;i++) {
			var res = "";
			
			while (m = this.extraRegexArray[i].exec(text))
			{
                if (m.length >= 2) {
				    res = m[1] + '@' + m[2] + "\r\n";
                }
			}
			
			if (res != "") 	return res;			
		}				
        
		return false;	
	}	    
}
// **************************************************************************************
function TestForWordpressCredentials(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/define\('DB_NAME',\s+'\w+'\);.*define\('DB_USER',\s+'\w+'\);.*define\('DB_PASSWORD',/
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText;
}
// **************************************************************************************
function TestForUsernameOrPasswordDisclosure(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
//								/(uid|user|username)\s?(:|=)\s*[\w|"|']+/i,
								/(pass|pwd|passwd|password)\s?(:|=)\s*[\w|"|']+/i
							];	
	
	var matchedText = matches.searchOnText(body);
	return matchedText;
}
// **************************************************************************************
function TestForTrojanShellScript(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/(<title>nsTView\s\v[\s\S]*?nst.void.ru<\/title>[\s\S]*?<b>nsTView\sv[\s\S]*?<a\shref=http:\/\/nst.void.ru\sstyle\='text-decoration:none;'>[\s\S]*?<b>Host:<\/b>[\s\S]*?<b>IP:<\/b>[\s\S]*?<b>Your\sip:<\/b>)/i,
								/(<\/font><\/b><\/td><td\sclass=td1\salign=left><input\stype=checkbox\sname=m\sid=m\svalue="1"><input\stype=text\sname=s_mask\ssize=82\svalue=".txt;.php">\*\s\(\s.txt;.php;.htm\s\)<input\stype=hidden\sname=cmd\svalue="search_text"><input\stype=hidden\sname=dir\svalue="[^"]*"><\/td><\/tr><\/table><\/)/i,
								/(<\/th><\/tr><tr><td><p\salign="left"><b>Software:&nbsp;[\s\S]*act=phpinfo"\starget="[\s\S]*<\/b>&nbsp;<\/p><p\salign="left"><b>Safe-mode:&nbsp;<font\scolor=[\s\S]*act=ftpquickbrute&d=C%3A%[\s\S]*act=selfremove"><)/i,
								/(<title>\sCrystal\sshell<\/title>[\s\S]*?<font size="1"\sface="Arial">Crystal hack shellphp<\/font><\/span>[\s\S]*2006-2007<\/span>)/i,
								/(<pre><form\saction\=""\sMETHOD\=GET\s>execute\scommand\:\s<input\stype="text"\sname="c"><input\stype="submit"\svalue="go"><hr><\/form>)/i,
								/(Usage\:\shttp\:\/\/target\.com\/simple-backdoor.php\?cmd=cat\+\/etc\/passwd)/i,
								/(<FORM\saction="[\s\S]*?"\smethod="POST">\n<input\stype=text\sname="\.CMD"\ssize=45\svalue="">\n<input\stype=submit\svalue="Run">\n<\/FORM>)/i,
								/(<title>[\s\S]*?WSO\s\d\.\d<\/title>[\s\S]*?<span>Execute:<\/span><br><input class='toolsInp' type=text name=c value=)/i,            
								/(<head><title>\n\s+ASPXSpy\d\.\d\s->\sBin\:\)\n<\/title>[\s\S]*<span\sid="PassLabel">Password:<\/span>)/i,
                                /(<h1>ASPX Shell by LT<\/h1>)/i
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText;
}
// **************************************************************************************
function TestForSourceCodeDisclosure(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
                                /(\<%[\s\S]*Response\.Write[\s\S]*%\>)/i,
								/^#\!\/[\s\S]*\/perl/i,
								/\<\?(php|\s+)[\x20-\x80\x0d\x0a\x09]+/i
							];
	var matchedText = matches.searchOnText(body);
			
	if (matchedText && matchedText.length > 1024)  return matchedText.substring(0, 1024) + ' ...'; 
	else return matchedText;
}
// **************************************************************************************
function TestForServerPathDisclosureUnix(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/[\s\t:><|\(\)\[\}](\/(var|www|usr|Users|user|tmp|etc|home|mnt|mount|root|proc)\/[\w\/\.]*(\.\w+)?)/
							];	
	    
	var matchedText = matches.searchOnText(body, 1);
    //trace(matchedText);   
    if (matchedText) {
        fileExt = matchedText.split('.').pop();
        fileExt = fileExt.toLowerCase();
        if (fileExt && fileExt != 'js') {
            dirs = matchedText.split("/");    
            if (dirs && dirs.length > 3) return matchedText;
        }
    }    
    return null; 
}
// **************************************************************************************
function TestForServerPathDisclosureWindows(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/([a-z])\:\\(program files|windows|inetpub|php|document and settings|www|winnt|xampp|wamp|temp|websites|apache|apache2|site|sites|htdocs|web|http)[\\\w]+(\.\w+)?/
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText;
}
// **************************************************************************************
function luhnCheck(val) {
    var sum = 0;
    for (var i = 0; i < val.length; i++) {
        var intVal = parseInt(val.substr(i, 1));
        if (i % 2 == 0) {
            intVal *= 2;
            if (intVal > 9) {
                intVal = 1 + (intVal % 10);
            }
        }
        sum += intVal;
    }
    return (sum % 10) == 0;
}
// **************************************************************************************
function TestForSensitiveDataCCorSSN(matches, body)
{
    // credit cards
    matches.plainArray = [
                        ];
    matches.regexArray = [
                            /\b((?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}))\b/
                        ];
	var matchedText = matches.searchOnText(body);
    if (matchedText && luhnCheck(matchedText)) {
        alert(matchedText, "Sensitive_data_CC.xml");
    }
    // SSN
    matches.plainArray = [
    ];
    matches.regexArray = [
                            /\b([0-9]{3}\-[0-9]{2}\-[0-9]{4})\b/
                        ];
    var matchedText = matches.searchOnText(body);
    if (matchedText) {
        alert(matchedText, "Sensitive_data_SSN.xml");
    }
}
// **************************************************************************************
function TestForRemoteSWFInclusion(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/<script[\s\S]*?\.addVariable\s*\(\s*("|')(skinName|baseurl|dataURL|csPreloader|onend)("|')[\s\S]*?<\/script>/i,
								/<object[\s\S]*?<param\s*name=\s*("|')(skinName|baseurl|dataURL|csPreloader|onend)("|')[\s\S]*?<\/object>/i			
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestForPhpInfo(matches, body)
{
		matches.plainArray = [
								'<title>phpinfo()</title>'
							];
		
		matches.regexArray = [
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText;
}
// **************************************************************************************
function TestForMicrosoftOfficeInfo(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/<o:DocumentProperties>[\s\S]*?<\/o:DocumentProperties>/
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestForInternalIP(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/\b(192\.168\.\d{1,3}\.\d{1,3}|172\.16\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/
							];	
	
	var matchedText = matches.searchOnText(body);			
	if (matchedText) {
		// don't report 127.0.0.1 ip addresses
		if (matchedText.indexOf('127.0.') == -1) return matchedText;
		else return "";
	}
	else return "";
}
// **************************************************************************************
function TestForEmailAddresses(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/[_a-zA-Z\d\-\.]+@([_a-zA-Z\d\-]+(\.[_a-zA-Z\d\-]+)+)/g
							];	
	    matches.extraRegexArray = [
                                /\s+var name\s*=\s*"([^\"]+)";\s+var domain\s*=\s*"([^\"]+)";\s+document.write\('\<a\shref=\\\"mailto:\'\s\+\sname\s+\+\s'@'\s\+\sdomain\s\+\s'\\">'\);\s+document.write\(name\s\+\s'@'\s\+\sdomain\s\+\s'<\/a>'\)\;/g
                            ];
	
	var matchedText = matches.searchObfuscatedEmailsOnText(body);	
    if (matchedText) addEmailAddressesForLaterUsage(matchedText);
	var matchedText = matches.searchEmailsOnText(body);	
    if (matchedText) addEmailAddressesForLaterUsage(matchedText);
	return matchedText;
}
// **************************************************************************************
function TestForColdFusionPathDisclosure(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/The Error Occurred in <b>([\s\S]*): line[\s\S]*<\/b><br>/i,
								/The error occurred while processing[\s\S]*Template: ([\s\S]*) <br>./i,
								/The error occurred while processing[\s\S]*in the template file ([\s\S]*)\.<\/p><br>/i							
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestForASPNETPathDisclosure(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/<title>Invalid\sfile\sname\sfor\smonitoring:\s'([^']*)'\.\sFile\snames\sfor\smonitoring\smust\shave\sabsolute\spaths\,\sand\sno\swildcards\.<\/title>/i
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestForEnvirnmentVariables(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/(GATEWAY_INTERFACE[\s\S]*?CGI\/1\.[01]|SERVER_PROTOCOL[\s\S]*?HTTP\/1\.[10]|COMMONPROGRAMFILES[\s\S]*?C:\\Program\sFiles\\Common\sFiles|java\.runtime\.name|sun\.boot\.library\.path|java\.vm\.version|java\.runtime\.version|sun\.jnu\.encoding|java\.vm\.specification\.vendor|java\.library\.path|sun\.boot\.class\.path)/i
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestForApplicationErrorMessages(matches, body)
{
	return genericErrorMessages.searchOnText(body);            
}
// **************************************************************************************
function TestForRSAPrivateKey(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/-----BEGIN RSA PRIVATE KEY-----(\n[^\-]+)+-----END RSA PRIVATE KEY-----/
							];	
	
	var matchedText = matches.searchOnText(body);
	return matchedText; 
}
// **************************************************************************************
function TestphpMyAdminSQLDump(matches, body)
{
		matches.plainArray = [
                                '-- phpMyAdmin SQL Dump',
							];
		
		matches.regexArray = [
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestMySQLDump(matches, body)
{
		matches.plainArray = [
                                '-- MySQL dump ',
							];
		
		matches.regexArray = [
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestMySQLConnectInfo(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
                                /mysql_[p]*connect\(["']{0,1}[a-z0-9\-\.]+["']{0,1}\s*,/
							];	
	
	var matchedText = matches.searchOnText(body);		
    // prevent false positives (mysql_connect in a documentation page). <? must be present
    if ((matchedText) && body.indexOf("<?") == -1) matchedText = false;
	return matchedText; 
}
// **************************************************************************************
function TestForFlashAllowScriptAccess(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/(<embed[\s\S]*?\s+AllowScriptAccess="always"\s+[\s\S]*<\/embed>)/i
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestStruts2DevMode(matches, body)
{
		matches.plainArray = [
                                'You are seeing this page because development mode is enabled.  Development mode, or devMode, enables extra',
							];
		
		matches.regexArray = [
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestDatabaseConnectionStringDisclosure(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
                                /((["']).*?SERVER=.*?;.*?DATABASE=.*?;.*(user[\s\S])?U?ID=.*?;.*?PASSWORD=.*?\1)/i,
            					/((["']).*?SERVER=.*?;.*(user[\s\S])?U?ID=.*?;.*?PASSWORD=.*?;.*?DATABASE=.*?;?\1)/i
							];	
	
	// first make sure that all the right patterns are in the response. don't search otherwise.	
	var lcBody = body.toLowerCase();
	
	if (lcBody.indexOf("server=") != -1 && lcBody.indexOf("password=") != -1 && lcBody.indexOf("database=") != -1)
	{
		var matchedText = matches.searchOnText(body);
		return matchedText; 
	}
	else return false;
}
// **************************************************************************************
function TestMySQLUsernameDisclosure(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/Access denied for user '(\w+)'@'[\s\S]*?' \(using password: \w+\)/
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestChromeLogger(response)
{
	var headerName = "";
	
	if (response.headerValue('X-ChromePhp-Data')) headerName = "X-ChromePhp-Data";
	else if (response.headerValue('X-ChromeLogger-Data')) headerName = "X-ChromeLogger-Data";
	
	if (headerName) return headerName; 
	else return false;
}
// **************************************************************************************
function TestSFWebDebugToolbar(matches, body)
{
		matches.plainArray = [
							];
		
		matches.regexArray = [
								/(<div id="sfwdt\w+" class="sf-toolbar" style="display: none">|<div id="sfWebDebug">)/
							];	
	
	var matchedText = matches.searchOnText(body);		
	return matchedText; 
}
// **************************************************************************************
function TestFormMailSpam(body, contentType)
{
	function CheckEmail(email) {
		var AtPos = email.indexOf("@");
		var StopPos = email.lastIndexOf(".");
		return (AtPos != -1 && StopPos != -1 && StopPos > AtPos);
	}	
	
	var pd = getParserData(body, contentType);
    if (pd) {
    	var forms = pd.getForms();
    	if (forms.count > 0) {	
    		for (var i=0; i<forms.count; i++) {
    				var myform = forms.item(i);
    				var formAction = myform.action;
    				if (formAction && formAction.toLowerCase().indexOf("mail") != -1) {    					
    					for (var j=0; j<myform.inputs.count; j++) {
    						var inputName = myform.inputs.item(j).name;
    						var inputType = myform.inputs.item(j).inputType.toLowerCase();
							var inputValue = myform.inputs.item(j).defaultValue;
    						if (    							
    							(inputType == 'hidden') &&
    							(inputValue.indexOf("@") != -1 && CheckEmail(inputValue))
    							)
    						{
								details = "Form action=[dark]'" + formAction + "'[/dark][break]";
								details = details + "Hidden input named [dark]" + inputName + "[/dark] contains the email address [dark]" + inputValue + "[/dark].";
								return details;
							}						
						}
					}
				}
			}
    	}
    	
    return false;
}
// **************************************************************************************
function TestDjangoDebugMode(matches, body)
{
    matches.plainArray = [];
    matches.regexArray = [/You're seeing this error because you have <code>DEBUG = True<\/code> in/];
    var matchedText = matches.searchOnText(body);
    return matchedText;
}
// **************************************************************************************
function TestRailsDevMode(matches, body)
{
	matches.plainArray = [];
	matches.regexArray = [/<title>Action Controller: Exception caught<\/title>/];
	var matchedText = matches.searchOnText(body);
	return matchedText;
}
// **************************************************************************************
function TestDWR(body)
{
	var patternStr = "<h2>Classes known to DWR:</h2>";
	
	if (body.indexOf(patternStr) != -1) 
		return patternStr; 
	
	return false;
}
// **************************************************************************************
function TestStrutsDevMode(matches, body)
{
    var patternStr = "You are seeing this page because development mode is enabled.  Development mode, or devMode, enables extra";
    if (body && body.indexOf("<title>Struts Problem Report</title>") != -1 && body.indexOf(patternStr) != -1) return patternStr
        else return false;
}
