#include string_helpers.inc;
#include helpers.inc;
function calssPostgresql(strHost, intPort)
{
	this.strHost = strHost;
	this.intPort = intPort;
	
	this.socket = new TSocket('tcp');
		
	this.socket.Host = strHost;
	this.socket.Port = intPort;
	this.socket.Timeout = 4;
	this.strLastError = "";
}
calssPostgresql.prototype.send = function(request)
{
	request = strFromWord(0) + strFromWord(request.length + 4) + request;
	trace("TX (" + request.length + "): " + request.toHexString());
	this.socket.Send(request);
}
calssPostgresql.prototype.receive = function()
{
	var data = "";
	this.strLastError = "";
	var head = this.socket.ReceiveBytes(1);
	if((head.length > 0) && ((head.getByteAt(0) == 'E'.getByteAt(0)) || (head.getByteAt(0) == 'R'.getByteAt(0))))
	{
		var head2 = this.socket.ReceiveBytes(4);
		if (head2.length < 4) 
		{
			trace("Invalid header received");
			return("");
		}
		var len = head2.getWordAt(2);
		if(len > 2048)
		{
			trace("Invalid lenght received");
			return("");
		}
		data = this.socket.ReceiveBytes(len - 4);
		trace("RX (" + len + "/" + head + "): " + data.toHexString());
		if(head.getByteAt(0) == 'E'.getByteAt(0))
		{
			// we have an error message
			this.strLastError = data.toReadableString();
			trace("Error: " + data.toReadableString());
			return("");
		}
		
		return(head + head2 + data);
	}
	trace("Invalid packet received");
	return("");
}
calssPostgresql.prototype.login = function(strUser, strPassword, strDb)
{
	this.socket.Connect();
	if (this.socket.IsConnected) 
	{
		var request = strFromWord(0x03) + strFromWord(0x00) +
			"user" + strFromByte(0x00) + strUser + strFromByte(0x00) +
			"database" + strFromByte(0x00) + strDb + strFromByte(0x00) +
			"client_encoding" + strFromByte(0x00) + "UNICODE" + strFromByte(0x00) +
			"DateStyle" + strFromByte(0x00) + "ISO" + strFromByte(0x00) +
			strFromByte(0x00);
			
		this.send(request);
		
		var data = this.receive();
		
		if(data.length > 0)
		{
			trace(data.toHexString());
			if (data.getByteAt(8) == 5) //MD5 autentification
			{
				var salt = data.getStringAt(9);
				var password = "md5" + PLAIN2MD5(PLAIN2MD5(strPassword + strUser) + salt);
				var passwordPacket = 'p' + strFromWord(0) + strFromWord(2 + 2 + password.length) + password;
				trace("TX (" + passwordPacket.length + "): " + passwordPacket.toHexString());
				this.socket.Send(passwordPacket);
				data = this.receive();
				if ((data.length > 0))// && (data.getWordAt(2) == 8)) 
				{
					this.socket.Close();
					return (1);
				}
			}
			this.socket.Close();
			return(0);
		}
	}
	else
	{
		trace("Can not open port.");
	}
	return(-1);
}
calssPostgresql.prototype.ping = function()
{
	this.socket.Connect();
	
	var strUser = 'root';
	var strDb = 'postgres';
	if (this.socket.IsConnected) 
	{
		var request = strFromWord(0x03) + strFromWord(0x00) +
			"user" + strFromByte(0x00) + strUser + strFromByte(0x00) +
			"database" + strFromByte(0x00) + strDb + strFromByte(0x00) +
			"client_encoding" + strFromByte(0x00) + "UNICODE" + strFromByte(0x00) +
			"DateStyle" + strFromByte(0x00) + "ISO" + strFromByte(0x00) +
			strFromByte(0x00);
			
		this.send(request);
		
		var data = this.receive();
		
		if ((data.length > 0) || (this.strLastError.length > 0)) 
		{
			this.socket.Close();
			return (true);
		}
	}
	else
	{
		trace("Can not open port.");
	}
	return(false);
}
