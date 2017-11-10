#include credentials_medium.inc;
#include cookies_helpers.inc;
var returnToken = "";
var namedToken = "";
var cookieName = "";
var cookieValue = "";
// **************************************************************************************							 
function alert(uri, username, password)
{	
	var ri = new TReportItem();
	ri.LoadFromFile("Weak_password.xml");
	ri.affects = uri;
	ri.alertPath = "Scripts/Joomla";	
	ri.details = "Username: [bold][dark]" +  username  + "[/dark][/bold], Password: [bold][dark]" + password + "[/dark][/bold]";;
	ri.name = "Joomla! Weak Password";
	ri.setHttpInfo(lastJob);
	AddReportItem(ri);	
}
// **************************************************************************************							 
function validCredentials(dir, uri, username, password)
{
	lastJob = new THTTPJob();
		
	lastJob.url = dir.url;
	lastJob.verb = 'POST';
	lastJob.URI = uri + "/administrator/index.php";
	lastJob.addCookies = false;
	lastJob.request.body = 'username=' + username + '&passwd=' + password + '&lang=&option=com_login&task=login&return=' + returnToken + '&' + namedToken + '=1';
	lastJob.request.addHeader('Cookie', cookieName + '=' + cookieValue, true);
	lastJob.request.addHeader('Content-type', 'application/x-www-form-urlencoded', true);
	lastJob.execute();	
	if (!lastJob.wasError)
	{
			lastJob.url = dir.url;
			lastJob.verb = 'GET';
			lastJob.URI = uri + "/administrator/index.php";
			lastJob.addCookies = false;
			lastJob.request.body = 'username=' + username + '&passwd=' + password + '&lang=&option=com_login&task=login&return=' + returnToken + '&' + namedToken + '=1';
			lastJob.request.addHeader('Cookie', cookieName + '=' + cookieValue, true);
			lastJob.request.addHeader('Content-type', 'application/x-www-form-urlencoded', true);
			lastJob.execute();
			
			if (!lastJob.wasError && lastJob.response.msg2 == 200 && !lastJob.notFound && lastJob.response.body.indexOf("<strong>Logout</strong>") != -1)
			{
				return true;
			}
	}	
	
	return false;
}
// **************************************************************************************							 
function detectJoomla(dir, uri)
{
	lastJob = new THTTPJob();
		
	lastJob.url = dir.url;
	lastJob.verb = 'GET';
	lastJob.URI = uri + "/administrator/index.php";
	lastJob.addCookies = false;
	lastJob.execute();
	if (!lastJob.wasError && lastJob.response.msg2 == 200 && !lastJob.notFound)
	{
		
		var m = /<input type="hidden" name="return" value="(\w+)"\s\/>/.exec(lastJob.response.body);
		if (m)  {		
			returnToken = m[1];
		}
		
		var m = /<input type="hidden" name="(\w{32})" value="1"\s\/>/.exec(lastJob.response.body);
		if (m)  {		
			namedToken = m[1];
		}
		// extract cookie
	    cookies = extractCookiesFromResponse(lastJob.response);
	    
	    for (name in cookies) {
	    	cookieName = name;
	        cookieValue = cookies[name];
	        break;
	    }
	    
	    if (cookieName && cookieValue && namedToken && returnToken) return true;		
	}	
	return false;		
}
// **************************************************************************************	
function test_for_joomla_weak_passwords(dir, rootDir)
{
	//trace("testing for weak passwords in " + rootDir);
	
	if (detectJoomla(dir, rootDir)) {
		//trace('joomla detected!');
		// look for false positives with invalid credentials
		if (validCredentials(dir, rootDir, randStr(8), randStr(8))) {
			return false;
		}
		
		var found = false;
		
		// start testing credentials
		for (var i=0;i<Usernames.length;i++) {
			var user = Usernames[i];
			//trace(user);
		
			for (var j=0;j<Passwords.length;j++) {
				var pass = Passwords[j];
					
				if (validCredentials(dir, rootDir, user, pass)) {
					alert(rootDir + "/administrator/index.php", user, pass);
					
					found = true;
					break;
				}
			}
			
			if (found) break;
		}
	}
}
/***********************************************************************************/
/* main entry point */
var lastJob = null;
