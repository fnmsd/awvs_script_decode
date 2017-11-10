#include string_helpers.inc;
function classTelnet(strHost)
{
	this.strHost = strHost;
	this.socket = new TSocket('tcp');
	this.socket.host 	= strHost;
	this.socket.timeout = 4;
}
classTelnet.prototype.negociateOptions = function(strInput)
{
	var returnBuffer = "";
	var filteredInput = "";
	var i;
	var option, optionType;
	for(i = 0; i < strInput.length; i++)
	{
		if(strInput.getByteAt(i) == 0xff) //this may be IAC (Interpret As Command)
		{	
			if((i + 1) < strInput.length)
			{
				optionType = strInput.getByteAt(i + 1);
				if(((optionType == 253) || (optionType == 254)) && ((i + 2) < strInput.length))
				{
					option = strInput.getByteAt(i + 2);
					// DO or DON'T do options // we respond with WON'T (252)
					returnBuffer = returnBuffer + strFromRawData(255, 252, option);
					i = i + 2;
					continue;
				}
				if(((optionType == 251) || (optionType == 252)) && ((i + 2) < strInput.length))
				{
					option = strInput.getByteAt(i + 2);
					// WILL or WON'T do options // we respond with DON'T (254)
					returnBuffer = returnBuffer + strFromRawData(255, 254, option);
					i = i + 2;
					continue;	
				}
				
				i = i + 1;
				continue;
			}
		}
		filteredInput = filteredInput + strFromRawData(strInput.getByteAt(i));
	}
	
	return(returnBuffer);
}
classTelnet.prototype.tryToLogIn = function(arrayCredentials, intStartIndex, intRecursion)
{
	var input;
	var output;
	var boolUsernameSent = false;
	var boolPasswordSent = false;
	var j = (intStartIndex == null) ? 0 : intStartIndex;
	
	intRecursion = (intRecursion) ? intRecursion : 0;
	if(intRecursion > (arrayCredentials.length + 1))
	{
		trace("Recursion end.");
		return ({
			"boolSuccess": false,
			"intIndex": j
		})
	}
		
	this.socket.timeout = 2; //let this timeout big because on ubuntu telnet start to respond after 3-4 seccond ....
	
	if (intStartIndex > arrayCredentials.length) 
	{
		trace("End.");
		return ({
			"boolSuccess": false,
			"intIndex": j
		})
	}
	
	if(this.socket.IsConnected)
		this.socket.Close();
	
	this.socket.Connect();
	
	if(!this.socket.IsConnected)
	{
		trace("Could not connect");
		return(null);		
	}
	
	for(var i = 0; i < 5; i++) // max 3 readings without sense then bye
	{
		input = this.socket.Receive(true);
		//trace("I: " + i);
		trace(input.toReadableString());
		
		output = this.negociateOptions(input);
		if (output.length > 0) 
		{
			i = i - 1; //reset the sense counter
			this.socket.send(output);
		}
		
		if((!boolUsernameSent) && (input.match(/username\s*?:/i) || input.match(/login\s*?:/i))) 
		{
			
			ScriptProgress(ComputeProgress(j, arrayCredentials.length));
			
			//we have to send the username ....
			trace('Sending username: ' + arrayCredentials[j].strUserName);
			this.socket.send(arrayCredentials[j].strUserName + strFromRawData(0x0d, 0x0a));
			boolUsernameSent = true;
			i = i - 1; //reset the sense counter
			continue;
		}
		
		if(boolUsernameSent)
		{
			if(
				input.match(/invalid/i) 	|| 
				input.match(/incorrect/i)	|| 
				input.match(/failed/i)	||
				input.match(/denied/i)
				)
				{
					trace("Invalid login");
					i = 0; //reset the sense counter
					var oldUserName = arrayCredentials[j].strUserName;
					j = j + 1;
					if(!boolPasswordSent)
					{
						trace("Optimizing: " + oldUserName);
						//password was not sent so we can optimise here a bit and jump over the combinations with the same user
						while((j < arrayCredentials.length) && (arrayCredentials[j].strUserName == oldUserName))
						{
							j ++;
						}
					}
					
					// it is look like invalid login, so we reset the login
					boolUsernameSent = false;
					boolPasswordSent = false;
					if(j >= arrayCredentials.length)
					{
						trace("Finished all combination.")
						return({"boolSuccess" : false, "intIndex" : j});
					}
					continue;
				}
			
			if(! boolPasswordSent && (input.match(/password\s*?:/i) || input.match(/passcode\s*?:/i)))
			{
				//we have to send the password...
				trace('Sending password: ' + arrayCredentials[j].strPassword);
				this.socket.send(arrayCredentials[j].strPassword + strFromRawData(0x0d, 0x0a));
				boolPasswordSent = true;
				i = i - 1; //reset the sense counter
				continue;
			}
			
			if(boolPasswordSent)
			{
				var reUserPrompt = new RegExp(arrayCredentials[j].strUserName + '@.*?:' );
				if(input.match(reUserPrompt))
				{
					trace("Login success");
					return({"boolSuccess" : true, "intIndex" : j});
				}
			}
			if(! this.socket.IsConnected)
			{
				// maybe we try to much and the server cicked us
				trace("Session expired.");
				return(this.tryToLogIn(arrayCredentials, j, intRecursion ++));
			}
		}
	}
	trace("Session hanging.");
	return(this.tryToLogIn(arrayCredentials, j, intRecursion ++));
}
classTelnet.prototype.Close = function()
{
	this.socket.close();
}