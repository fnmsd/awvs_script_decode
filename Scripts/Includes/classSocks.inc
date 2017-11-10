#include string_helpers.inc;
#include ip_helpers.inc;
function classSocks(strHost, intPort, strVersion)
{
	this.socket 		= new TSocket('tcp');
	this.intPort		= intPort;
	this.strHost 		= strHost;
	this.strVersion 	= strVersion;
	this.socket.host 	= strHost;
	this.socket.port 	= intPort;
	this.socket.timeout = 4;
	
	this.strUserName = "";
	this.strPassword = "";
	
	this.intAutentType = 0;
	
	this.clientID		= 'acunetix';
	
	this.strVersion = strVersion;
	this.intConnectionStatus = 0;
	this.strConnectionError = "";
}
classSocks.prototype.close = function()
{
	this.socket.Close();
}
classSocks.prototype.InitiateConnection = function(strHost, intPort, intType)
{
	var request;
	this.intConnectionStatus = 0;
	this.strConnectionError = "";
	this.address = "";
	this.port = 0;
	
	this.autType = 0;
	if (this.strVersion == '4') 
	{
		var isStrHostIP = true;
		var ip = IPToData(strHost);
		if (ip == '') {
			isStrHostIP = false;
			ip = strFromRawData(0, 0, 0, 1);
		}
			
		var request = 	strFromRawData(0x04) +		//protocol 4
						strFromRawData(intType) +	//connect
						strFromWord(intPort) + 		//destination port
						ip + 						//ip
						this.clientID + strFromRawData(0);
						
		if (!isStrHostIP) //we have a 4a request here
			request = request + strHost + strFromRawData(0);
		
		this.socket.Connect();
		if (this.socket.IsConnected) {
			this.socket.Send(request);
			
			var data = this.socket.Receive(8);
			
			if ((data.length != 8) || (data.getByteAt(0) != 0)) {
				trace('Invalid socks 4 response.');
				this.socket.Close();
				return (-1);
			}
			
			switch (data.getByteAt(1)) {
				case 0x5a:
					this.strConnectionError = "";
					this.intConnectionStatus = 0x5a;
					return (1);
				case 0x5b:
					this.strConnectionError = "request rejected or failed";
					this.intConnectionStatus = 0x5b;
					this.socket.Close();
					return (0);
				case 0x5c:
					this.strConnectionError = "request failed because client is not running identd (or not reachable from the server)";
					this.intConnectionStatus = 0x5c;
					this.socket.Close();
					return (0);
				case 0x5d:
					this.strConnectionError = "request failed because client's identd could not confirm the user ID string in the request";
					this.intConnectionStatus = 0x5d;
					this.socket.Close();
					return (0);
				default:
					trace('Invalid socks 4 response..');
					this.socket.Close();
					return (-1);
			}
		}
		else {
			trace("Can not conect to socks server");
			this.socket.Close();
			return (-2);
		}
	}
	
	if (this.strVersion == '5')
	{
		//0x00 - No authentication
		//0x01 - GSSAPI
		//0x02 - Username/Password
		
		var request = 	strFromRawData(0x05) +			//protocol 5
						strFromRawData(0x01) +			//number of autentification types
						strFromRawData(this.intAutentType);	//the type of autentification
		
		this.socket.Connect();
		
		if (this.socket.IsConnected)
		{
			this.socket.Send(request);
			var data = this.socket.ReceiveBytes(2);
			
			if((data.length != 2) || data.getByteAt(0) != 5)
			{
				trace('Invalid socks 5 response. (authent initialization)');
				this.socket.Close();
				return (-1);
			}
			
			switch(data.getByteAt(1))
			{
				case 0: //no autentification needed
					this.autType = 0;
					break;
				case 1: //GSSAPI
					this.autType = 1;
					break;
				case 2: //username password
					this.autType = 2; 
					request = 	strFromByte(1) +
								strFromByte(this.strUserName.length) + this.strUserName + 
								strFromByte(this.strPassword.length) + this.strPassword;
					this.socket.Send(request);
					data = this.socket.ReceiveBytes(2);
					if((data.length != 2) || ((data.length == 2) && (data.getByteAt(0) != 1)))
					{
						trace('Invalid socks 5 response. (password autentification)');
						this.socket.Close();
						return (-1);
					}
					if(data.getByteAt(1) != 0) // autentification failure
					{
						this.strConnectionError = "Autentification error";
						this.intConnectionStatus = 0x0a;
						this.socket.Close();
						return(0);	
					}				
					break;
				case 0xff:
					this.strConnectionError = "Unsuported autentification type requested.";
					this.intConnectionStatus = 0x0b;
					this.socket.Close();
					return(0);
				default:
					trace('Invalid socks 5 response. (autent method)');
					this.socket.Close();
					return(-1);					
			}
			
			request = 	strFromRawData(0x05) +		//protocol 5
						strFromRawData(intType) +	//0x01 = establish a TCP/IP stream connection
    												//0x02 = establish a TCP/IP port binding
    												//0x03 = associate a UDP port
						strFromRawData(0x00); 			//reserved
			
			if (IsStringIPAddress(strHost)) 
			{
				request = request + strFromRawData(0x01); //IPv4 address
				request = request + IPToData(strHost);
			}
			else 
			{
				request = request + strFromRawData(0x03); //Domain name
				request = request + strFromByte(strHost.length) + strHost;
			}
			
			request = request + strFromWord(intPort);
					
			this.socket.Send(request);
			
			data = this.socket.ReceiveBytes(4);
			
			if((data.length < 4) || (data.getByteAt(0) != 5) || (data.getByteAt(2) != 0))
			{
				trace('Invalid socks 5 response. (handshake header)');
				this.socket.Close();
				return (-1);
			}
			
			var intHostType = data.getByteAt(3);
			
			switch(intHostType)
			{
				case 0x01:	//IPv4 address
					this.address = this.socket.ReceiveBytes(4);
					if(this.address.length != 4)
					{
						trace('Invalid socks 5 response. (IPv4 address)');
						this.socket.Close();
						return (-1);
					}
					break;
				case 0x03:	//Domain name
					var addressSize = this.socket.ReceiveBytes(1);
					if(addressSize.length != 1)
					{
						trace('Invalid socks 5 response. (Domain name length)');
						this.socket.Close();
						return (-1);
					}
					this.address = this.socket.ReceiveBytes(addressSize.getByteAt(0));
					if(this.address.length != addressSize.getByteAt(0))
					{
						trace('Invalid socks 5 response. (Domain name)');
						this.socket.Close();
						return (-1);
					}					
					break;
				case 0x04:	//IPv6 address
					trace('Unsuported address IPV6');
					this.socket.Close();
					return (-1);
				default:
					trace('Invalid socks 5 response. (intHostType)');
					this.socket.Close();
					return (-1);
			}
			
			var port = this.socket.ReceiveBytes(2);
			if(port.length != 2)
			{
				trace('Invalid socks 5 response. (port)');
				this.socket.Close();
				return (-1);
			}
			this.port = port.getWordAt(0);		
			
			switch(data.getByteAt(1))
			{
				case 0x00:	//request granted
					this.strConnectionError = "";
					this.intConnectionStatus = 0x00;
					return(1);
				case 0x01:	//general failure
					this.strConnectionError = "general failure";
					this.intConnectionStatus = 0x01;
					this.socket.Close();
					return(0);
				case 0x02:	//connection not allowed by ruleset
					this.strConnectionError = "connection not allowed by ruleset";
					this.intConnectionStatus = 0x02;
					this.socket.Close();
					return(0);
				case 0x03:	//network unreachable
					this.strConnectionError = "network unreachable";
					this.intConnectionStatus = 0x03;
					this.socket.Close();
					return(0);
				case 0x04:	//host unreachable
					this.strConnectionError = "host unreachable";
					this.intConnectionStatus = 0x04;
					this.socket.Close();
					return(0);
				case 0x05: 	//connection refused by destination host
					this.strConnectionError = "connection refused by destination host";
					this.intConnectionStatus = 0x05;
					this.socket.Close();
					return(0);
				case 0x06:	//TTL expired
					this.strConnectionError = "TTL expired";
					this.intConnectionStatus = 0x06;
					this.socket.Close();
					return(0);
				case 0x07:	//command not supported / protocol error
					this.strConnectionError = "command not supported / protocol error";
					this.intConnectionStatus = 0x07;
					this.socket.Close();
					return(0);
				case 0x08: 	//address type not supported
					this.strConnectionError = "address type not supported";
					this.intConnectionStatus = 0x08;
					this.socket.Close();
					return(0);
				default:
					trace('Invalid socks 5 response. (success)');
					this.socket.Close();
					return(-1);
			}	
			
		}
		else 
		{
			trace("Can not conect to socks server");
			return (-2);
		}
	}
	
	trace("Unknown socks protocol version.");
	return(-1);
}
classSocks.prototype.AssociateUDP = function(strHost, intPort)
{
	this.close();
	return this.InitiateConnection(strHost, intPort, 0x03);
}
classSocks.prototype.Bind = function(strHost, intPort)
{
	this.close();
	return this.InitiateConnection(strHost, intPort, 0x02);
}
classSocks.prototype.Connect = function(strHost, intPort)
{
	this.close();
	return this.InitiateConnection(strHost, intPort, 0x01);
}