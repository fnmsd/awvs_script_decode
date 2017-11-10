#include "string_helpers.inc";
#include "debug_helpers.inc";
intMaxASNChilds = 100;
function ASN_value(data, strEncoding, strClass, strForm, intDepth)
{
	this.data = data;
	this.strEncoding = strEncoding;
	this.childs = new Array();
	this.strType = "";
	this.strClass = strClass;
	this.strForm = strForm;
	if(intDepth == null) this.intDepth = 0; else  this.intDepth = intDepth;
}
ASN_value.prototype.getIdent = function()
{
	var strTab = ""; 
	for(var i = 0; i < this.intDepth; i++) strTab = strTab + '\t';
	return(strTab);
}
ASN_value.prototype.feed = function()
{
	if(this.strEncoding == "DER")
		this.feedDer();
}
ASN_value.prototype.toString = function()
{
	return(this.getIdent() + this.strType + ": " + this.data.toHexString() + "\n");
}
ASN_value.prototype.asHexDump = function()
{
	return(this.data.toHexStringNoSP());
}
ASN_value.prototype.asInteger = function(boolLitleEndian, boolSilent)
{
	if((this.strType == "INTEGER") || (this.strType == "BIT_STRING")|| (this.strType == "OCTET_STRING"))
	{
		if(boolLitleEndian == null) boolLitleEndian = false;
		if(boolSilent == null) boolSilent = false;
		var retval = 0;
		if (this.data.length > 4)
		{
			if(boolSilent) return(0);
			throw "This type can't be represented on one integer!";
		}
		if(boolLitleEndian)
		{
			for(var i = this.data.length - 1; i >= 0; i++)
				retval = retval * 256 + this.data.getByteAt(i);
		}
		else
		{
			for(var i = 0; i < this.data.length; i++)
				retval = retval * 256 + this.data.getByteAt(i);
		}
		return(retval);
	}
	if(this.strType == "NULL") return(0);
	if(boolSilent) return(0);
	throw "This type can't be represented as integer";
}
ASN_value.prototype.asPrintableString = function()
{
	result = "";
	var strReadables = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
	for(var i = 0; i < this.data.length; i++)
		if (strReadables.indexOf(this.data.charAt(i), 0) >= 0)
			result = result + this.data.charAt(i);
	return(result);
}
function ASN_SEQUENCE(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "SEQUENCE";
	this.feed();
}
ASN_SEQUENCE.prototype = new ASN_value;
ASN_SEQUENCE.prototype.toString = function()
{
	var strResult = this.getIdent() + "SEQUENCE:"  + '\n';
	for(var i = 0; i < this.childs.length; i++)
	{
		strResult = strResult + this.childs[i].toString();
	}
	return(strResult);
}
function ASN_INTEGER(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "INTEGER";
}
ASN_INTEGER.prototype = new ASN_value;
function ASN_BIT_STRING(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "BIT_STRING";
}
ASN_BIT_STRING.prototype = new ASN_value;
function ASN_OCTET_STRING(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "OCTET_STRING";
}
ASN_OCTET_STRING.prototype = new ASN_value;
function ASN_NULL(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "NULL";
}
ASN_NULL.prototype = new ASN_value;
ASN_NULL.prototype.toString = function()
{
	return(this.getIdent() + "NULL" + "\n");
}
function ASN_OBJECT_IDENTIFIER(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "OBJECT_IDENTIFIER";
	this.numbers = new Array();
	if(data.length == 0) return; 
	//handle first byte, which contains first two numbers
	this.numbers.push(parseInt(data.getByteAt(0)/40));
	this.numbers.push(data.getByteAt(0)%40);
	
	var x = 1;
	while(x < data.length)
	{
		var num = 0; 
		// keep reading until MSB == 0
		var bitcount = 0;
		do
		{
			bitcount = bitcount + 7;
			if(bitcount > 63) 
			{
				// we're about to overflow our long
				throw "OBJECT IDENTIFIER element too long; max is 63 bits";
			}
			var b = data.getByteAt(x++);
			num <<= 7;
			num |= (b & 0x7f);
		}while( (b & 0x80) != 0 );
		
		this.numbers.push(num);
	}	
}
ASN_OBJECT_IDENTIFIER.prototype = new ASN_value;
ASN_OBJECT_IDENTIFIER.prototype.asPrintableString = function()
{
	var strResult = ""
	for(var i = 0; i < this.numbers.length; i++)
	{
		if(i != 0) strResult = strResult + '.';
		strResult = strResult + this.numbers[i];  
	}
	return(strResult);
}
ASN_OBJECT_IDENTIFIER.prototype.toString = function()
{
	return(this.getIdent() + "OBJECT_IDENTIFIER: " + this.asPrintableString() + '\n');
}
function ASN_SET(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "SET";
	this.feed();
}
ASN_SET.prototype = new ASN_value;
ASN_SET.prototype.toString = function()
{
	var strResult = this.getIdent() + "SET:"  + '\n';
	for(var i = 0; i < this.childs.length; i++)
	{
		strResult = strResult + this.childs[i].toString();
	}
	return(strResult);
}
function ASN_PrintableString(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "PrintableString";
}
ASN_PrintableString.prototype = new ASN_value;
ASN_PrintableString.prototype.toString = function()
{
	return(this.getIdent() + "PrintableString: " + this.data + "\n");
}
function ASN_UTF8String(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "UTF8String";
}
ASN_UTF8String.prototype = new ASN_value;
ASN_UTF8String.prototype.toString = function()
{
	return(this.getIdent() + "UTF8String: " + this.data + "\n");
}
function ASN_T61String(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "T61String";
}
ASN_T61String.prototype = new ASN_value;
ASN_T61String.prototype.toString = function()
{
	return (this.getIdent() + "T61String: " + this.asPrintableString() + "\n");
}
function ASN_IA5String(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = this.getIdent() + "IA5String";
}
ASN_IA5String.prototype = new ASN_value;
ASN_IA5String.prototype.toString = function()
{
	return (this.getIdent() + "IA5String: " + this.asPrintableString() + "\n");
}
function ASN_UTCTime(data, strEncoding, strClass, strForm, intDepth)
{
	ASN_value.call(this, data, strEncoding, strClass, strForm, intDepth);
	this.strType = "UTCTime";
	this.boolUTCTime = true;
	this.intYear = 0;
	this.intMonth = 0;
	this.intDay = 0;
	this.intHour = 0;
	this.intMinute = 0;
	this.intSecond = 0;
	this.intMilliSecond = 0;
	
	if(data.length > 13) this.boolUTCTime = false;
	var x = 0
	if(this.boolUTCTime)
	{
		if( x + 2 > data.length)
			throw "ASN error";
		this.intYear = (data.charAt(x) - '0')*10 + (data.charAt(x + 1) - '0'); 
		if(this.intYear < 50) this.intYear = 2000 + this.intYear;
		else this.intYear = 1900 + this.intYear;
		x = x + 2;
	}
	else
	{
		if( x + 4 > data.length)
			throw "ASN error";
		this.intYear = (data.charAt(x) - '0')*1000 + (data.charAt(x + 1) - '0')*100 + (data.charAt(x + 2) - '0')*10 + (data.charAt(x + 3) - '0');
		x = x + 4;
	}
	
	if( x + 2 > data.length)
		throw "ASN error";
	this.intMonth = (data.charAt(x) - '0')*10 + (data.charAt(x + 1) - '0');
	x = x + 2;
	
	if( x + 2 > data.length)
		throw "ASN error";
	this.intDay = (data.charAt(x) - '0')*10 + (data.charAt(x + 1) - '0');
	x = x + 2;
	
	if( x + 2 > data.length)
		throw "ASN error";
	this.intHour = (data.charAt(x) - '0')*10 + (data.charAt(x + 1) - '0');
	x = x + 2;
	if( x + 2 > data.length)
		throw "ASN error";
	this.intMinute = (data.charAt(x) - '0')*10 + (data.charAt(x + 1) - '0');
	x = x + 2;
	
	if( x + 2 <= data.length)
	{	
		if((data.charAt(x) >= '0') && (data.charAt(x) <= '9'))
		{
			this.intSecond = (data.charAt(x) - '0')*10 + (data.charAt(x + 1) - '0');
			x = x + 2;
		}
	}
	
	if(!this.boolUTCTime) //skip millieseconds
	{
		while((x < data.length) && (data.charAt(x) != '+') && (data.charAt(x) != '-') && (data.charAt(x) != 'Z'))
			x ++;
	}
	
	var boolUTC = false;
	var intOffset = 0;
	
	if( x + 1 <= data.length)
	{
		if(data.charAt(x) == 'Z')
		{
			boolUTC = true;
			x ++;
		}
		else
		if((data.charAt(x) == '-') || (data.charAt(x) == '+'))
		{
			x++;
			if( x + 4 > data.length)
				throw "ASN error";
			intOffset = ((data.charAt(x) - '0')*100 + (data.charAt(x + 1) - '0'))*60*60*1000;
			x = x + 2;
			intOffset = intOffset + ((data.charAt(x) - '0')*100 + (data.charAt(x + 1) - '0'))*60*1000;
			x = x + 2;
		}
	}
	
	this.date = new Date();
	
	if(!boolUTC)
	{	
		this.date.setFullYear(this.intYear);
		this.date.setMonth(this.intMonth - 1);
		this.date.setDate(this.intDay);
		this.date.setHours(this.intHour);
		this.date.setMinutes(this.intMinute);
		this.date.setSeconds(this.intSecond);
		this.date.setMilliseconds(this.intMilliSecond);
	}
	else
	{
		this.date.setUTCFullYear(this.intYear);
		this.date.setUTCMonth(this.intMonth - 1);
		this.date.setUTCDate(this.intDay);
		this.date.setUTCHours(this.intHour);
		this.date.setUTCMinutes(this.intMinute);
		this.date.setUTCSeconds(this.intSecond);
		this.date.setUTCMilliseconds(this.intMilliSecond);
	}
	
	if( x < data.length)
		throw "ASN error ++";
	this.date.setTime(this.date.getTime() + intOffset);	
}
ASN_UTCTime.prototype = new ASN_value;
ASN_UTCTime.prototype.asPrintableString = function()
{
	//todo: handle non boolUTCTime also
	return(this.date.toString());
}
ASN_UTCTime.prototype.toString = function()
{
	return(this.getIdent() + "UTCTime: " + this.asPrintableString() + "\n");
}
ASN_value.prototype.feedDer = function()
{ 
	var x = 0;
	for(var i = 0; i < intMaxASNChilds; i++)
	{
		if(x >= this.data.length) //end reached
			break;
		
		var intBlockType = this.data.getByteAt(x ++);
		var intBlockLength = this.data.getByteAt(x ++);
		var strForm = "Primitive";
		
		if(intBlockType &  0x20) //Constructed method
			strForm = "Constructed";
		
		if((strForm == "Constructed")&&(intBlockLength == 0x80)) //indefinite-length method (ends with 00 00)
		{
			//todo calculate length
		}
		else 
		{
			if ((intBlockLength & 0x80) == 0x80)
		    {
				var l = 0;
				for(var j = 0; j < (intBlockLength & 0x7f); j ++) l = l * 0x100 + this.data.getByteAt(x++);
				intBlockLength = l;			
		    }
		}
		
		var strClass ='';
	    switch((intBlockType & (0xc0) ) >> 6)
	    {
	     case 0:
	    	 strClass = 'Universal';
	        break;
	     case 1:
	    	 strClass = 'Application';
	        break;
	     case 2:
	    	 strClass = 'Context-specific';
	        break;
	     case 3:
	    	 strClass = 'Private';
	        break;
	    }
	    
	    switch(intBlockType & 0x1f)
		{
			case 0x0:
					if (strForm == "Constructed")
						this.childs.push(new ASN_SEQUENCE(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
					else throw "Incorect intBlockType!";
				break;
			case 0x02: //INTEGER
				this.childs.push(new ASN_INTEGER(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x03: //BIT STRING
				this.childs.push(new ASN_BIT_STRING(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x04: //OCTET STRING
				this.childs.push(new ASN_OCTET_STRING(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x05: //NULL
				this.childs.push(new ASN_NULL(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x06: //OBJECT IDENTIFIER
				this.childs.push(new ASN_OBJECT_IDENTIFIER(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x0c: //UTF8String
				this.childs.push(new ASN_UTF8String(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break
			case 0x10: //SEQUENCE and SEQUENCE OF
				this.childs.push(new ASN_SEQUENCE(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x11: //SET
				this.childs.push(new ASN_SET(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x13: //PrintableString
				this.childs.push(new ASN_PrintableString(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x14: //T61String
				this.childs.push(new ASN_T61String(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x16: //IA5String
				this.childs.push(new ASN_IA5String(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			case 0x17: //UTCTime"
				this.childs.push(new ASN_UTCTime(this.data.substr(x, intBlockLength), this.strEncoding, strClass, strForm, this.intDepth + 1));
				break;
			default :
				trace("Unknown ASN block type: " + (intBlockType & 0x1f) + " content: " + this.data.substr(x, intBlockLength));
				throw "Unknown ASN block type";
				
		}
		x = x + intBlockLength;
	}
}
