//string_helpers.inc
// strFromRawData(0x02, 0x00, 0x02, 0x00, 0x00, 0x00);
function strFromRawData()
{
	var strTmp = "";
	for(var i = 0; i < arguments.length; i++) 
		strTmp = strTmp + strFromByte(arguments[i]);
	return(strTmp);
}
function CRLF()
{
	return strFromRawData(0x0d, 0x0a);
}
	
//strFromRawHex("020002000000020");
function strFromRawHex(strValue)
{
	var retval = "";
	for (var i = 0; i < (strValue.length - 1); i=i+2) 
	{
		retval = retval + strFromByte(parseInt('0x' + strValue.charAt(i) + strValue.charAt(i + 1)));
	}
	
	return(retval);
}
// strFromData(["string","value",[0 - if zero terminated]], ['byte',3], ["word","value",[true/false - bigendian]])
function strFromData()
{
	var strTmp = "";
	for(var i = 0; i < arguments.length; i++)
	{
		var strType = (arguments[i][0] == null) ? "none" : arguments[i][0];
		var v1 = (arguments[i][1] == null) ? null : arguments[i][1];
		var v2 = (arguments[i][2] == null) ? null : arguments[i][2];
		
		switch(strType)
		{
			case "byte":
				strTmp = strTmp + strFromByte(v1);
				break;
			case "word":
				strTmp = strTmp + strFromWord(v1, v2);
				break;
			case "3byte":
				strTmp = strTmp + strFrom3Byte(v1, v2);
				break;
			case "long":
				strTmp = strTmp + strFromLong(v1, v2);
				break;
			case "string":
				strTmp = strTmp + v1;
				if(v2 == 0) strTmp = strTmp + strFromByte(0);
				break;
			case "fill":
				for(var j = 0; j < v1; j++)
					strTmp = strTmp + strFromByte(v2);
				break;
			default:
				trace("strFromData undefined type: " + strType);
		}
	}
	return(strTmp);
}
function strHexUnixTime()
{
	var dDate = new Date();
	var d = parseInt(((dDate.getTime()- dDate.getMilliseconds())/1000)>>0); 
	return(strFromRawData( (d >> 24) & 0xff, (d >> 16) & 0xff, (d >> 8) & 0xff, (d >> 0) & 0xff));
}
function strHexUTCUnixTime()
{
	var dDate = new Date();
	var d = parseInt((Date.UTC(dDate.getUTCFullYear(),dDate.getUTCMonth(),dDate.getUTCDate(),dDate.getUTCHours(),dDate.getUTCMinutes(),dDate.getUTCSeconds(),dDate.getUTCMilliseconds())/1000) >> 0);
	return(strFromRawData( (d >> 24) & 0xff, (d >> 16) & 0xff, (d >> 8) & 0xff, (d >> 0) & 0xff));
}
function strFromByte(intValue)
{
	intValue = (intValue == null) ? 0 : intValue;
	var strTmp = String.fromCharCode(intValue & 0xff);
	return(strTmp);
}
function strFromWord(intValue, boolBigEndian)
{
	intValue = (intValue == null) ? 0 : intValue;
	boolBigEndian = (boolBigEndian == null) ? true : boolBigEndian;
	var a0 = String.fromCharCode(intValue & 0xff);
	var a1 = String.fromCharCode((intValue >> 8) & 0xff);
	var strTmp = "";
	if(boolBigEndian)
		strTmp = a1 + a0;
	else
		strTmp = a0 + a1;
	return(strTmp);
}
function strFrom3Byte(intValue, boolBigEndian)
{
	intValue = (intValue == null) ? 0 : intValue;
	boolBigEndian = (boolBigEndian == null) ? true : boolBigEndian;
	var a0 = String.fromCharCode(intValue & 0xff);
	var a1 = String.fromCharCode((intValue >> 8) & 0xff);
	var a2 = String.fromCharCode((intValue >> 16) & 0xff);
	var strTmp = "";
	if(boolBigEndian)
		strTmp = a2 + a1 + a0;
	else
		strTmp = a0 + a1 + a2;
	return(strTmp);
}
function strFromLong(intValue, boolBigEndian)
{
	intValue = (intValue == null) ? 0 : intValue;
	boolBigEndian = (boolBigEndian == null) ? true : boolBigEndian;
	var a0 = String.fromCharCode(intValue & 0xff);
	var a1 = String.fromCharCode((intValue >> 8) & 0xff);
	var a2 = String.fromCharCode((intValue >> 16) & 0xff);
	var a3 = String.fromCharCode((intValue >> 24) & 0xff);
	var strTmp = "";
	if(boolBigEndian)
		strTmp = a3 + a2 + a1 + a0;
	else
		strTmp = a0 + a1 + a2 + a3;
	return(strTmp);
}
String.prototype.toStr = function(intFrom, intLength)
{
	intFrom = (intFrom == null) ? 0 : intFrom;
	intLength = (intLength == null) ? (this.length - intFrom) : intLength;
	var strTmp = "";
	var strReadables = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
	for(var i = 0; i < intLength; i++)
	{
		if (strReadables.indexOf(this.charAt(i),0) < 0)
		{
			var strHex = this.getByteAt(i).toString(16);
			if (strHex.length < 2) strHex = '0' + strHex;
				strTmp = strTmp + '0x' + strHex;
			strTmp = strTmp + ';';
			continue;
		}
		strTmp = strTmp + this.charAt(i);
	}
	return(strTmp);
}
// show only printable characters
String.prototype.toReadableString = function(intFrom, intLength)
{
	intFrom = (intFrom == null) ? 0 : intFrom;
	intLength = (intLength == null) ? (this.length - intFrom) : intLength;
	var strTmp = "";
	var strReadables = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
	var boolInNonreadable = false;
	for(var i = 0; i < intLength, intFrom + i < this.length; i++)
	{
		if (strReadables.indexOf(this.charAt(intFrom + i),0) < 0)
		{
			if(!boolInNonreadable)
			{
				strTmp = strTmp + '.';
				boolInNonreadable = true;
			}
			continue;
		}
		strTmp = strTmp + this.charAt(intFrom + i);
		boolInNonreadable = false;
	}
	return(strTmp);
}
String.prototype.toHexString2 = function(intFrom, intLength)
{
	intFrom = (intFrom == null) ? 0 : intFrom;
	intLength = (intLength == null) ? (this.length - intFrom) : intLength;
	var strTmp = "";
	for(var i = 0; i < intLength, intFrom + i < this.length; i++)
	{
		var strHex = this.getByteAt(intFrom + i).toString(16);
		if (strHex.length < 2) strHex = '0' + strHex;
		strTmp = strTmp + '\\x' + strHex;
	}
	return(strTmp);
}
String.prototype.toHexString = function(intFrom, intLength)
{
	intFrom = (intFrom == null) ? 0 : intFrom;
	intLength = (intLength == null) ? (this.length - intFrom) : intLength;
	var strTmp = "";
	for(var i = 0; i < intLength, intFrom + i < this.length ; i++)
	{
		if (strTmp.length > 0) strTmp = strTmp + " ";
		var strHex = this.getByteAt(intFrom + i).toString(16);
		if (strHex.length < 2) strHex = '0' + strHex;
		strTmp = strTmp + strHex;
	}
	return(strTmp);
}
String.prototype.toHexString16B = function(intFrom, intLength)
{
	var strReadables = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
	
	intFrom = (intFrom == null) ? 0 : intFrom;
	intLength = (intLength == null) ? (this.length - intFrom) : intLength;
	var strTmp = "";
	for(var i = 0; i < intLength, intFrom + i < this.length ; i++)
	{
		if (strTmp.length > 0) strTmp = strTmp + " ";
		var strHex = this.getByteAt(intFrom + i).toString(16);
		if (strHex.length < 2) strHex = '0' + strHex;
		
		if (i > 0 && i%16 == 0) {
			for (var j=i-16;j<i;j++) {
				if (strReadables.indexOf(this.charAt(intFrom + j),0) < 0) strTmp = strTmp + ".";
				else strTmp = strTmp + this.charAt(intFrom + j);
			}
			strTmp = strTmp + "\n";
		}
		
		strTmp = strTmp + strHex;
	}
	return(strTmp);
}
String.prototype.toHexStringNoSP = function(intFrom, intLength)
{
	intFrom = (intFrom == null) ? 0 : intFrom;
	intLength = (intLength == null) ? (this.length - intFrom) : intLength;
	var strTmp = "";
	for(var i = 0; i < intLength, intFrom + i < this.length ; i++)
	{
		var strHex = this.getByteAt(intFrom + i).toString(16);
		if (strHex.length < 2) strHex = '0' + strHex;
		strTmp = strTmp + strHex;
	}
	return(strTmp);
}
String.prototype.setByteAt = function(intValue, intIndex)
{
	intIndex = ((intIndex < 0) || (intIndex == null)) ? 0 : intIndex;
	if(intIndex >= this.length) 
		trace("setByteAt range error!");
	var strTmp = this.substr(0, intIndex) + strFromByte(intValue) + this.substr(intIndex + 1, this.length - (intIndex + 1));
	return(strTmp);
}
String.prototype.set3ByteAt = function(intValue, intIndex)
{
	intIndex = ((intIndex < 0) || (intIndex == null)) ? 0 : intIndex;
	if(intIndex >= (this.length - 2)) 
		trace("set3ByteAt range error!");
	var strTmp = this.substr(0, intIndex) + strFromWord(intValue, boolBigEndian) + this.substr(intIndex + 3, this.length - (intIndex + 3));
	return(strTmp.substr(0, this.length));
}
String.prototype.setWordAt = function(intValue, intIndex, boolBigEndian)
{
	intIndex = ((intIndex < 0) || (intIndex == null)) ? 0 : intIndex;
	if(intIndex >= (this.length - 1)) 
		trace("setWordAt range error!");
	var strTmp = this.substr(0, intIndex) + strFromWord(intValue, boolBigEndian) + this.substr(intIndex + 2, this.length - (intIndex + 2));
	return(strTmp.substr(0, this.length));
}
String.prototype.setLongAt = function(intValue, intIndex, boolBigEndian)
{
	intIndex = ((intIndex < 0) || (intIndex == null)) ? 0 : intIndex;
	if(intIndex >= (this.length - 3)) 
		trace("setLongAt range error!");
	var strTmp = this.substr(0, intIndex) + strFromLong(intValue, boolBigEndian) + this.substr(intIndex + 4, this.length - (intIndex + 4));
	return(strTmp.substr(0, this.length));
}
String.prototype.getByteAt = function(intIndex)
{
	intIndex = ((intIndex == null) || (intIndex < 0)) ? 0 : intIndex;
	if(intIndex >= this.length) 
	{
		trace("getByteAt range error! " + intIndex + ">=" + this.length);
		return(0);
	}
	return(0xff & this.charCodeAt(intIndex + 0));
}
String.prototype.getWordAt = function(intIndex, boolBigEndian)
{
	intIndex = ((intIndex == null) || (intIndex < 0)) ? 0 : intIndex;
	if(intIndex >= (this.length - 1)) 
	{
		trace("getWordAt range error!");
		return(0);
	}
	boolBigEndian = (boolBigEndian == null) ? true : boolBigEndian;
	
	if(boolBigEndian)
		return ((this.getByteAt(intIndex + 0) << 8) + this.getByteAt(intIndex + 1));
	else
		return ((this.getByteAt(intIndex + 1) << 8) + this.getByteAt(intIndex + 0));
}
String.prototype.get3ByteAt = function(intIndex, boolBigEndian)
{
	intIndex = ((intIndex == null) || (intIndex < 0)) ? 0 : intIndex;
	if(intIndex >= (this.length - 2)) 
	{
		trace("get3ByteAt range error!");	
		return(0);
	}
	boolBigEndian = (boolBigEndian == null) ? true : boolBigEndian;
	
	if(boolBigEndian)
		return ((this.getByteAt(intIndex + 0) << 16) + (this.getByteAt(intIndex + 1) << 8) + this.getByteAt(intIndex + 2));
	else
		return ((this.getByteAt(intIndex + 2) << 16) + (this.getByteAt(intIndex + 1) << 8) + this.getByteAt(intIndex + 0));
}
//javascript integer is signed long !!!!!!!
String.prototype.getLongAt = function(intIndex, boolBigEndian)
{
	intIndex = ((intIndex == null) || (intIndex < 0)) ? 0 : intIndex;
	if(intIndex >= (this.length - 3)) 
	{
		trace("getLongAt range error!");	
		return(0);
	}
	boolBigEndian = (boolBigEndian == null) ? true : boolBigEndian;
	
	if(boolBigEndian)
		return ((this.getByteAt(intIndex + 0) << 24) + (this.getByteAt(intIndex + 1) << 16) + (this.getByteAt(intIndex + 2) << 8) + this.getByteAt(intIndex + 3));
	else
		return ((this.getByteAt(intIndex + 3) << 24) + (this.getByteAt(intIndex + 2) << 16) + (this.getByteAt(intIndex + 1) << 8) + this.getByteAt(intIndex + 0));
}
String.prototype.getNullTerminatedStringAt = function(intIndex, boolIncludeTheNull)
{
	intIndex = ((intIndex == null) || (intIndex < 0)) ? 0 : intIndex;
	boolIncludeTheNull = (boolIncludeTheNull == null) ? false : boolIncludeTheNull;
	var strTmp = "";
	if(intIndex >= this.length) 
	{
		trace("getNullTerminatedStringAt range error!");	
		return("");
	}
	for(var i = intIndex; i < this.length; i++)
	{
		if(this.getByteAt(i) == 0) break;
		strTmp = strTmp + this.charAt(i);
	}	
	if(boolIncludeTheNull) strTmp = strTmp + strFromByte(0);
	return(strTmp);
}
String.prototype.getStringAt = function(intIndex, intLength)
{
	intLength = (intLength == null) ? this.length : intLength;
	intIndex = ((intIndex == null) || (intIndex < 0)) ? 0 : intIndex;
	if(intIndex >= this.length) 
	{
		trace("getStringAt range error!");	
		return("");
	}
	var i,j;
	var strTmp = "";
	for(i = intIndex, j = 0;(i < this.length) && (j < intLength); i++, j++ )
	{
		strTmp = strTmp + this.charAt(i);
	}
	return(strTmp);
}
String.prototype.endsWith = function(suffix) {
    return this.indexOf(suffix, this.length - suffix.length) !== -1;
};
String.prototype.startsWith = function (str){
    return this.indexOf(str) == 0;
};
String.prototype.indexOfCi = function(searchstring) {
    if (searchstring && searchstring.length > 0) return this.toLowerCase().indexOf(searchstring.toLowerCase());
    else return -1;
}
String.prototype.repeat= function(n){
    n= n || 1;
    return Array(n+1).join(this);
}
String.prototype.trim=function(){
    return this.replace(/^\s\s*/, '').replace(/\s\s*$/, '');
};
String.prototype.replaceAll = function (find, replace) {
    var str = this;
    return str.replace(new RegExp(find.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'g'), replace);
};
String.prototype.trunc = String.prototype.trunc ||
      function(n){
          return this.length>n ? this.substr(0,n-1)+' ... ' : this;
      };
      
function removeCaseInsensitiveDuplicatesFromStringArray (arr) {
    if (arr.length == 0) return [];
    var sorted_arr = arr.sort(function(a, b){
            if(a.toLowerCase() < b.toLowerCase()) return -1;
            if(a.toLowerCase() > b.toLowerCase()) return 1;
            return 0;
        });
    
    var result = [sorted_arr[0].toLowerCase()];
    for (var i=1; i<sorted_arr.length; i++) {
        if (result[result.length-1] != sorted_arr[i].toLowerCase())
            result.push(sorted_arr[i].toLowerCase());
    }
    return result;
}
