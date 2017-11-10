#include string_helpers.inc;
#include debug_helpers.inc;
#include helpers.inc;
function mySQLHandlerClass(strHost, intPort)
{
	this.socket = new TSocket('tcp');
	this.socket.host = strHost;
	this.socket.port = intPort;
	this.socket.timeout = 5;
	
	this.error = null;
	this.intErrorNumber = 0;
	this.strErrorState = "";
	this.strError = "";
	this.intSec = 0;
}
mySQLHandlerClass.prototype.disconect = function()
{
	this.socket.close();
}
mySQLHandlerClass.prototype.connect = function()
{
	this.socket.connect();
	if(this.socket.IsConnected)
	{
		trace('mySQLHandlerClass.connect: connected');
		return(true);
	}
	else
	{
		trace('mySQLHandlerClass.connect: can not connect');
		return(false);
	}
}
mySQLHandlerClass.prototype.getSalt = function(bits)
{
  if (this.isProto41Supported() && ((bits ==null) || (bits == 20))) 
    return(this.scramble_buff + this.scramble_buff2);
  else 
    return(this.scramble_buff);
}
mySQLHandlerClass.prototype.isErrorPacket = function(packet)
{
	if((packet == null) || packet.len < 1)
	{
		trace('isErrorPacket: invalid packet');
		this.strError = "isErrorPacket: invalid packet";
		this.intErrorNumber = 0;
		this.strErrorState = "";
		return(null);
	}
	if(packet.data.getByteAt(0) == 0xff)
	{
		this.error = packet;
		this.strError = "";
		
		this.intErrorNumber = packet.data.getWordAt(1, false);
		//Version 4.1.
		if (packet.data.getByteAt(3) == "#".getByteAt(0))
		{
			this.strErrorState = packet.data.getStringAt(4,4);
			this.strError = packet.data.getStringAt(9,4000);
			trace('Error (4.1): ' + this.intErrorNumber + ', ' + this.strErrorState + ', ' + this.strError);
		}
		//Pre-version 4.1.
		else
		{
			this.strErrorState = "";
			this.strError = packet.data.getStringAt(3,4000);
			trace('Error (pre 4.1): ' + this.intErrorNumber + ', ' + this.strError);
		}
		
		return(true);
	}	
	else
	{
		this.error = null;
		this.intErrorNumber = 0;
		this.strErrorState = "";
		this.strError = "";
		return(false);
	}
}
mySQLHandlerClass.prototype.open = function()
{
	//trace('mySQLHandlerClass.open: starting');
	if(this.connect() == false) 
	{
		return(-1);
	}
	var packet = this.receivePacket();
	if((packet == null) || packet.len < 1)
	{
		trace("Error in mySQLHandlerClass.open: invalid packet");
		this.socket.close();
		return(-1);
	}
	if(this.isErrorPacket(packet))
	{
		return(0);
	}
	else
	{
		this.error = null;
	}
	
	/*
	Bytes                        Name
	 -----                        ----
	 1                            protocol_version
	 n (Null-Terminated String)   server_version
	 4                            thread_id
	 8                            scramble_buff
	 1                            (filler) always 0x00
	 2                            server_capabilities
	 1                            server_language
	 2                            server_status
	 13                           (filler) always 0x00 ...
	 13                           rest of scramble_buff (4.1)
	*/
	
	this.protocol_version 	= packet.data.getByteAt(0);
	this.server_version 	= packet.data.getNullTerminatedStringAt(1);
	var n = this.server_version.length;
	
	this.thread_id_1 		= packet.data.getWordAt(2 + n, false);
	this.thread_id_0 		= packet.data.getWordAt(4 + n, false);
	
	this.str_thread_id 		= '0x' + this.thread_id_0.toString(16) + ((this.thread_id_1.toString(16).length > 1) ? this.thread_id_1.toString(16) : '0' + this.thread_id_1.toString(16));
	
	this.scramble_buff 		= packet.data.getStringAt(6 + n, 8);
	this.filler		 		= packet.data.getByteAt(14 + n);
	
	this.server_capabilities= packet.data.getWordAt(15 + n, false);
	
	var arrayCaps = new Array("LONG_PASSWORD", "FOUND_ROWS", "LONG_FLAG", "CONNECT_WITH_DB", 
			"NO_SCHEMA", "COMPRESS", "ODBC", "LOCAL_FILES", "IGNORE_SPACE", "PROTOCOL_41",
			"INTERACTIVE", "SSL", "IGNORE_SIGPIPE", "TRANSACTIONS", "SECURE_CONNECTION", "MULTI_STATEMENTS");
	
	this.str_server_capabilities = "";
	for( var i = 0; i < 16; i++)
	{
		if((this.server_capabilities & (1<<i)) > 0) 
		{
			if(this.str_server_capabilities.length > 0) this.str_server_capabilities += ", "
			this.str_server_capabilities += arrayCaps[i];
		}
	}
	
	this.server_language	= packet.data.getByteAt(17 + n);
	this.server_status		= packet.data.getWordAt(18 + n, false);
	
	var arrayStatus = new Array("IN_TRANS", "AUTOCOMMIT", "MORE_RESULTS", "MORE_RESULTS_EXISTS", "QUERY_NO_GOOD_INDEX_USED", "QUERY_NO_INDEX_USED");
	this.str_server_status = "";
	for( var i = 0; i < 6; i++)
	{
		if((this.server_status & (1<<i)) > 0) 
		{
			if(this.str_server_status.length > 0) this.str_server_status += ", "
			this.str_server_status += arrayStatus[i];
		}
	}
	
	
	this.scramble_buff2 = "";
	
	if ((this.server_capabilities & 512) && (packet.data.length > 44 + n))
	    this.scramble_buff2 = packet.data.getStringAt(33 + n, 12); // 
	
	trace('mySQLHandlerClass.open: success');
	return (1);
}
mySQLHandlerClass.prototype.isProto41Supported = function()
{
  if ((this.server_capabilities & 512) != 0) return(true);
  return(false);
}
mySQLHandlerClass.prototype.hash323 = function(strPass)
{
	var i;
	var n1 = 1345345333;
	var n2 = 305419889;
	var add = 7;
	for( i = 0; i < strPass.length; i++)
	{
		n1 = n1 ^ (((n1 & 63) + add) * strPass.getByteAt(i) + n1 * 256);
		n2 = (n2 * 256) ^ n1;
		add = add + strPass.getByteAt(i);
	}
	var result = new Array(2);
	result[0] = n1 & 0x3FFFFFFF;
	result[1] = n2 & 0x3FFFFFFF;
	return (result);
}
mySQLHandlerClass.prototype.hash323_10 = function(strPass)
{
	var salt = this.scramble_buff;
	var p = this.hash323(strPass);
	var s = this.hash323(salt);
	var seed1 = p[0] ^ s[0];
	var seed2 = p[1] ^ s[1];
	var i, msg ="", rng;
	for(i = 0; i < salt.length; i++)
	{
		seed1 = (seed1 * 3 + seed2) % 230 - 1;
		seed2 = (seed1 + seed2 + 33) % 230 - 1;
		rng = seed1 / (230 - 1);
		msg = msg + strFromByte((64 + rng * 31) & 0xff);
	}
	var msg2 = "";
	for(i = 0; i < salt.length; i++)
	{
		seed1 = (seed1 * 3 + seed2) % 230 - 1;
		seed2 = (seed1 + seed2 + 33) % 230 - 1;
		rng = seed1 / (230 - 1);
		msg2 = msg2 + strFromByte((msg.getByteAt(i) ^ (64 + rng * 31)) & 0xff);
	}
	return(msg2);
}
mySQLHandlerClass.prototype.login = function(strUser, strPass, strDb, flags, maxPacketSize, charset)
{
	flags = (flags == null) ? this.server_capabilities : flags;
	maxPacketSize = (maxPacketSize == null) ? 0xffff : maxPacketSize;
	serverLanguage = (charset == null) ? this.server_language : charset;
	var data = '';
	var scramble = '';
	if(strPass.length == 0)
	{
		trace("Login using password = no");
		data = strFromData(["word", 0x85A6], ["word", 0x0200], ["word", 0x0000], ["word", 0x0040], ["byte", serverLanguage], ["fill", 23, 0], ["string", strUser, 0],["byte", 0]);
		if((strDb != null) && (strDb.length > 0))
			data = data + strDb + strFromByte(0);
		this.sendPacket(data);
		packet = this.receivePacket();
		if(this.isErrorPacket(packet))
			return(0);
		else
			return(1);
	}
	else
	{
		if(this.isProto41Supported()) //4.1x
		{
			trace("Login using password = yes, with protocol 4.1x/10 (" + strUser + ")");
			var scramble = "";
			
			var hash1 = SHA1(strPass);
			var hash2 = SHA1(hash1);
			var hash3 = SHA1(this.getSalt() + hash2);
			scramble = "";
			for (var i = 0; i < hash3.length; i++)
				scramble = scramble + strFromByte(hash3.getByteAt(i) ^ hash1.getByteAt(i));
			
			data = strFromData(["word", 0x85A6], ["word", 0x0200], ["word", 0x0000], ["word", 0x0040], ["byte", serverLanguage], ["fill", 23, 0], ["string", strUser, 0],  ["byte", scramble.length], ["string", scramble]);
			if((strDb != null) && (strDb.length > 0))
				data = data + strDb + strFromByte(0);
			
			this.sendPacket(data);
			packet = this.receivePacket();
			
			if(packet == null)
				return(-2);
			if(this.isErrorPacket(packet))
				return(0);
			else
				{
					//check for fallback
					if(packet.data.getByteAt(0) == 0xfe)
					{
						trace("Falback not implemented yet");
						return(-1);
						// not working
						var scramble = strFromData(["string", this.hash323_10(strPass)], ["byte", 0]);
						this.sendPacket(scramble);
						packet = this.receivePacket();
						
						if(packet == null)
							return(-2);
						
						if(this.isErrorPacket(packet))
							return(0);
						else
							return(1);
					}	
					else
						return(1);
				}
		}
		else
		{
			trace("Login with protocol 3.x not implemented");
			return (-1);
		}
	}
}
mySQLHandlerClass.prototype.receivePacket = function()
{
	var header = this.socket.ReceiveBytes(4);
	//trace(header.toHexString2());
	var packet = {"len" : 0, "num" : 0, "data" : "" };
	if(header.length != 4)
	{
		trace("Error in mySQLHandlerClass.receivePacket: bad header");
		return(null);
	}
	packet.len = header.get3ByteAt(0, false);
	packet.num = header.getByteAt(3);
	this.intSec = packet.num;
	
	packet.data = this.socket.ReceiveBytes(packet.len);
	trace( 'RX: (' + packet.len + ', ' + packet.num + ') ' + packet.data.toHexString2());
	
	if(packet.data.length != packet.len)
	{
		trace("Error in mySQLHandlerClass.receivePacket: bad data length");
		return(null);
	}
	
	return(packet);
}
mySQLHandlerClass.prototype.sendPacket = function(strBuffer)
{
	this.intSec = this.intSec + 1;
	if(strBuffer == null)
	{
		trace("mySQLHandlerClass.sendPacket: strBuffer argumentMissing");
		return(null);
	}
	var intLength = strBuffer.length;
	var data = strFromData(["3byte", intLength, false], ["byte", this.intSec], ["string", strBuffer]);
	trace('TX: (' + intLength + ', ' + this.intSec + ') ' + data.toHexString());
	this.socket.send(data);
	return(strBuffer.length + 4);
}
