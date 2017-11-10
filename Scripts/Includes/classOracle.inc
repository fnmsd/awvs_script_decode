#include string_helpers.inc;
function classOracle(strHost, intPort)
{
	this.strHost = strHost;
	this.intPort = intPort;
	
	this.socket = new TSocket('tcp');
		
	this.socket.Host = strHost;
	this.socket.Port = intPort;
	this.socket.Timeout = 4;
	this.strLastError = "";
}
classOracle.prototype.pingHTTP = function(host, port)
{
	if (host == null) host = this.strHost; 
	if (port == null) port = 8080;
	var httpRequest = new THTTPJob();
	httpRequest.url.url = "http://" + host + "/apex/apex";
	httpRequest.url.port = port;
	httpRequest.method = "GET";
	httpRequest.execute();
	if(!httpRequest.wasError)
	{
		var headers = httpRequest.response.headersString;
		if((headers.length > 0) && (headers.match(/Server: Oracle XML DB/) != null))
			return(true); 
	}
	return(false);
}
classOracle.prototype.sendCommand = function(command)
{
	var commandLength = command.length;
	var packetLength = command.length + 58;
	
	var packet = strFromRawData(
		(packetLength >> 8) & 255 , packetLength & 255, 
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
		0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00, 
		0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01, 
		(commandLength >> 8) & 255 , commandLength & 255, 
		0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00, 
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00
		) + command;
		
	trace ("TX (" + packet.length + "):" + packet.toHexString());
	
	this.socket.Send(packet);
}
classOracle.prototype.receive = function()
{
	this.strLastError = "";
	var header = this.socket.ReceiveBytes(8);
	if(header.length < 5)
	{
		trace("Reception error.");
		return("");
	}
	
	if (header.getByteAt(4) == 4) 
	{
		this.strLastError = "A TNS service is running on this port but it is refusing connection (Reported code: 0x" + header.getByteAt(4).toHexString() + ")";
		return("");
	}
	
	var responseLength = header.getWordAt(0);
	
	if(responseLength <= 8)
		return("");
		
	var data = this.socket.ReceiveBytes(responseLength - 8)
	
	trace("RX (" + data.length + "):" + header + data);
	return(header + data);
}
classOracle.prototype.isTNSSecurityOff = function()
{
	if(!this.socket.IsConnected)this.socket.Connect();
	if (this.socket.IsConnected) 
	{
		var command = "(CONNECT_DATA=(COMMAND=VERSION))";
		this.sendCommand(command);
		
		var packet = this.receive();
		if(packet.length > 0)
		{
			if(packet.match(/SECURITY=OFF/)) //security is turned off
				return(true);
		}
	}
	return(false);	
}
classOracle.prototype.getVersion = function()
{	
	if(!this.socket.IsConnected)this.socket.Connect();
	if(this.socket.IsConnected)
	{
		var command = "(CONNECT_DATA=(COMMAND=VERSION))";
		this.sendCommand(command);
		
		var packet1 = this.receive();
		if(this.strLastError.length > 0)
		{
			// we have oracle but connection is refused
			return( "Oracle TNSLSNR (unknown)");
		}
		
		if(packet1.length == 0)
		{
			return("");
		}
		
		if(packet1.getByteAt(4)!= 0x02)
		{
			//we have oracle but wrong packet
			trace("Wrong packet1 type.");
			return( "Oracle TNSLSNR (unknown)");
		}
		var packet2 = this.receive();
		if((packet2.length == 0) || (packet2.getByteAt(4)!= 0x06)) 
		{
			//we have oracle but wrong seccond packet
			trace("Wrong packet2 type.");
			return( "Oracle TNSLSNR (unknown)");
		}
		
		var packet3 = this.receive();
		
		return(packet2.getStringAt(10));
			
	}
	else
	{
		trace("Can not connect to host");
		return("");		
	}
}
