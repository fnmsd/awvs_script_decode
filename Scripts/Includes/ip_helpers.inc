// returns true for a private ip address
function IsPrivateIpAddress(ip){
	var ret = false;
	
	//trace(ip);
	
	var re = new RegExp("(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})");
	var res = re.exec(ip);
	//traceObject(res);
	if(res != undefined && res.length >= 0)
	{
		ret = true;
	}	
	return ret;
}
//returns true if the given string is IP address 
function IsStringIPAddress(ip)
{
	var re = new RegExp("([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})");
	var res = re.exec(ip);
	if(res != undefined && res.length >= 0)
		return(true);	
	return(false);
}
function IPToData(ip)
{
	var result = "";
	if(! IsStringIPAddress(ip)) 
		return("");
	var match = ip.match(/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/);
	if(match)
		return(
			String.fromCharCode(match[1] & 0xff) + 
			String.fromCharCode(match[2] & 0xff) + 
			String.fromCharCode(match[3] & 0xff) + 
			String.fromCharCode(match[4] & 0xff));
	return("");
}
