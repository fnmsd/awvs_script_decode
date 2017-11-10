var RndCharArray = [
					'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
					'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
					'0','1','2','3','4','5','6','7','8','9'
					];
/*************************************************************************************************************************/
function SHA1(strValue)
{
	var tmp = Plain2SHA1(strValue);
	var retval = "";
	for(var i = 0; i <= 40 - 2; i = i + 2)
		retval = retval + String.fromCharCode(parseInt('0x' + tmp.charAt(i) + tmp.charAt(i + 1)));
	return(retval);		
}
/*************************************************************************************************************************/
function MD5(strValue)
{
	var tmp = Plain2MD5(strValue);
	var retval = "";
	for(var i = 0; i <= 40 - 2; i = i + 2)
		retval = retval + String.fromCharCode(parseInt('0x' + tmp.charAt(i) + tmp.charAt(i + 1)));
	return(retval);		
}
/*************************************************************************************************************************/
function randStr(count)
{
	var res = "";
	for (var i=0; i<count; i++) {
		res = res + RndCharArray[random(RndCharArray.length)];
	}
	return res;
}
/*************************************************************************************************************************/
function getBaseDomain(url)
{	
	var parts = url.host.toLowerCase().split(".");
	
	if (parts.length > 2) {
		if (parts[parts.length-2] == 'co' || parts[parts.length-2] == 'org' || parts[parts.length-2] == 'com' || parts[parts.length-2] == 'net'){
			return parts[parts.length-3] + "." + parts[parts.length-2] + "." + parts[parts.length-1];
		}
		else return parts[parts.length-2] + "." + parts[parts.length-1];
	}	
	else return url.host;
}
/*************************************************************************************************************************/
function getFileName83(f) {
	var fileName = getFileName(f);
	var fileExt  = getFileExt(f);
	// remove invalid chars
	fileName = fileName.replace('.', '');
	fileName = fileName.replace(' ', '');
	fileName = fileName.replace('"', '');
	fileName = fileName.replace('\\', '');
	fileName = fileName.replace('/', '');
	fileName = fileName.replace('[', '');
	fileName = fileName.replace(']', '');
	fileName = fileName.replace(':', '');
	fileName = fileName.replace(';', '');
	fileName = fileName.replace('=', '');
	fileName = fileName.replace(',', '');	
	if (fileName.length > 6) 
	fileName = fileName.substr(0, 6) + '~1';
		
	// reduce extension to .3 chars
	if (fileExt.length > 4)
	fileExt = fileExt.substr(fileExt, 0, 4);		
		
	var fname = fileName;
	if (fileExt) fname = fileName + "." + fileExt;
		
	return fname.toUpperCase();
}
/*************************************************************************************************************************/
function ComputeProgress(current, max)
{
	var res = 0;
	if (current<=max && current > 0 && max > 0) 
		res = Math.floor(100*current/max);
	return res;
}
/*************************************************************************************************************************/
function capitalize(string)
{
    return string.charAt(0).toUpperCase() + string.slice(1);
}
/*************************************************************************************************************************/
function eliminateDuplicates(arr) {
  var i,
      len=arr.length,
      out=[],
      obj={};
  for (i=0;i<len;i++) {
    obj[arr[i]]=0;
  }
  for (i in obj) {
    out.push(i);
  }
  return out;
}
/*************************************************************************************************************************/
function encodeStringAsChar(str, separator) {
    var out = "";
    for (var i=0; i<str.length; i++) {
        out = out + 'CHAR(' + str.charCodeAt(i) + ')' + separator;
    }
    if (out) {
        // remove the last +
        out = out.substring(0, out.length-1);
    }
    return out;
}
/*************************************************************************************************************************/
if(!Array.prototype.indexOf) {
    Array.prototype.indexOf = function(needle) {
        for(var i = 0; i < this.length; i++) {
            if(this[i] === needle) {
                return i;
            }
        }
        return -1;
    };
}
/*************************************************************************************************************************/
function getPathDirectory(path)
{	
	var pathDir = "";
	
	lastSlash = path.lastIndexOf("/");
	if (lastSlash > 0) {
		pathDir = path.substr(0, lastSlash);
	}
	else {
		pathDir = "/";
	}
	
	return pathDir;
}
/*************************************************************************************************************************/
/*************************************************************************************************************************/
function extractHostForCredentials()
{	
	var host = "";
	var match = scanHost.match(/([\w+]\.)?(\w+)/);
	if (match) host = match[2];
	
	return host;
}
/*************************************************************************************************************************/
/*************************************************************************************************************************/
function getURL(url){
    if (debug) trace("getURL from " + url);
    var http = new THTTPJob();
    http.url = new TURL(url);
    http.verb = 'GET';
    http.execute();
    if (!http.wasError && !http.notFound && http.response.msg2 == 200) {
        if (debug) trace("getURL returned " + url.length + " bytes");
        return http.response.body;
    }
    if (debug) trace("getURL returned empty string");
    return "";
}
/*************************************************************************************************************************/