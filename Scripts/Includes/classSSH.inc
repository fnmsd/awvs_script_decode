function classSSH(strHost, intPort, intTimeOut)
{
	this.ssh = new TSSHImpl();
	this.ssh.Host = strHost;
	this.ssh.Port = intPort;
	this.ssh.Timeout = (intTimeOut == null) ? 5000 : intTimeOut * 1000;
	
	this.info = new Object();
}
classSSH.prototype.checkFileForGivenHash = function(strFileName, strHash)
{
	trace("Checking " + strHash + " in " + strFileName);
	var fs = new ActiveXObject("scripting.FileSystemObject"); 
	var file;
	try
	{
		file = fs.OpenTextFile(strFileName);
	}
	catch(e)
	{
		LogError("Can not open file: " + strFileName);
		return({"error" : true});
	}
	var strLine = "";
	while(!file.AtEndOfStream)
	{  
		strLine = file.ReadLine();
		if(strLine.match(strHash))
		{
			file.Close();
			return({"error" : false, "strLine" : strLine});
		}
	}
	
	file.Close(); 
	
	return({"error" : false, "strLine" : ""});
}
classSSH.prototype.checkForRandomBug = function()
{
	this.getInfo();
	if(this.info.ServerKeyFingerprint.length == 0)
	{
		trace("Can not connect to SSH server: " + this.ssh.LastError);
		return(null);
	}
	
	trace("Connection to server successful");
	
	var retval = 0;
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_dsa_1024_keys.txt", this.ssh.ServerKeyFingerprint);
	if((! retval.error) && (retval.strLine != "")) return('DSA 1024 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_2048_keys.txt", this.ssh.ServerKeyFingerprint);
	if((! retval.error) && (retval.strLine != "")) return('RSA 2048 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_1023_keys.txt", this.ssh.ServerKeyFingerprint);
	if((! retval.error) && (retval.strLine != "")) return('RSA 1023 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_1024_keys.txt", this.ssh.ServerKeyFingerprint);
	if((! retval.error) && (retval.strLine != "")) return('RSA 1024 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_2047_keys.txt", this.ssh.ServerKeyFingerprint);
	if((! retval.error) && (retval.strLine != "")) return('RSA 2047 bit:' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_4096_keys.txt", this.ssh.ServerKeyFingerprint);
	if((! retval.error) && (retval.strLine != "")) return('RSA 4096 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_8192_keys.txt", this.ssh.ServerKeyFingerprint);
	if((! retval.error) && (retval.strLine != "")) return('RSA 8192 bit: ' + retval.strLine);
	
	return("");
		
}
classSSH.prototype.getInfo = function()
{
	this.info = new Object();
	
	if(this.ssh.Active)
		this.ssh.Close();
	
	this.ssh.User = "root";
	this.ssh.Pass = "nopassword";
	
	this.ssh.Connect();
	this.info.ServerKeyFingerprint = this.ssh.ServerKeyFingerprint;
	
	this.info.SshVersion = "Unknown version.";
	if(this.ssh.SshVersion == 0 ) this.info.SshVersion = "SSH1"; 
	if(this.ssh.SshVersion == 1 ) this.info.SshVersion = "SSH2";
		
	var arrayEncryptionAlgorithm = new Array(
		"3DES",		 		// 0 (0x00)
		"BLOWFISH", 		// 1 (0x01) 
		"TWOFISH256",		// 2 (0x02) 
		"TWOFISH192",		// 3 (0x03)
		"TWOFISH128",		// 4 (0x04)
		"AES256",			// 5 (0x05)
		"AES192",			// 6 (0x06)
		"AES128",			// 7 (0x07)
		"SERPENT256",		// 8 (0x08)
		"SERPENT192",		// 9 (0x09)
		"SERPENT128",		// 10 (0x0A)
		"ARCFOUR",			// 11 (0x0B)
		"IDEA",				// 12 (0x0C)
		"CAST128",			// 13 (0x0D)
		"NONE",				// 14 (0x0E)
		"DES",				// 15 (0x0F) 
		"AES128 CTR",		// 16 (0x10)
		"AES192 CTR",		// 17 (0x11)
		"AES256 CTR",		// 18 (0x12)
		"3DES CTR",			// 19 (0x13)
		"BLOWFISH CTR",		// 20 (0x14)
		"TWOFISH128 CTR",	// 21 (0x15)
		"TWOFISH192 CTR",	// 22 (0x16)
		"TWOFISH256 CTR",	// 23 (0x17)
		"SERPENT128 CTR",	// 24 (0x18)
		"SERPENT192 CTR",	// 25 (0x19)
		"SERPENT256 CTR",	// 26 (0x1A)
		"IDEA CTR",			// 27 (0x1B)
		"CAST128 CTR",		// 28 (0x1C)
		"ARCFOUR128",		// 29 (0x1D)
		"ARCFOUR256"		// 30 (0x1E)
		); 
 
 	if ((this.ssh.EncryptionAlgorithmClientToServer >= 0) && (this.ssh.EncryptionAlgorithmClientToServer < arrayEncryptionAlgorithm.length))
 		this.info.EncryptionAlgorithmClientToServer = arrayEncryptionAlgorithm[this.ssh.EncryptionAlgorithmClientToServer];
	else
		this.info.EncryptionAlgorithmClientToServer = "Unknown";
	
	if ((this.ssh.EncryptionAlgorithmServerToClient >= 0) && (this.ssh.EncryptionAlgorithmServerToClient < arrayEncryptionAlgorithm.length))
 		this.info.EncryptionAlgorithmServerToClient = arrayEncryptionAlgorithm[this.ssh.EncryptionAlgorithmServerToClient];
	else
		this.info.EncryptionAlgorithmServerToClient = "Unknown";
	
	var arrayMacAlgorithm = new Array(
		"HMAC with SHA-1 digest", 							//0x00
		"HMAC with SHA-1 digest, truncated to 96 bits", 	//0x01
		"HMAC with MD5 digest", 							//0x02
		"HMAC with MD5 digest, truncated to 96 bits",		//0x03
		"HMAC with RIPEMD digest",							//0x04
		"Unknown",
		"Unknown",
		"HMAC with SHA-256 digest",							//0x07
		"HMAC with SHA-256 digest, truncated to 96 bits",	//0x08
		"MAC algorithm is not used"							//0x09
	); 
	
	if ((this.ssh.MacAlgorithmClientToServer >= 0) && (this.ssh.MacAlgorithmClientToServer < arrayMacAlgorithm.length))
 		this.info.MacAlgorithmClientToServer = arrayMacAlgorithm[this.ssh.MacAlgorithmClientToServer];
	else
		this.info.MacAlgorithmClientToServer = "Unknown";
	
	if ((this.ssh.MacAlgorithmServerToClient >= 0) && (this.ssh.MacAlgorithmServerToClient < arrayMacAlgorithm.length))
 		this.info.MacAlgorithmServerToClient = arrayMacAlgorithm[this.ssh.MacAlgorithmServerToClient];
	else
		this.info.MacAlgorithmServerToClient = "Unknown";
	
	
	var arrayPublicKeyAlgorithm = new Array(
		"Certificate contains an RSA key",
		"Certificate is signed using RSA digital signature with MD2 digest",
		"Certificate is signed using RSA digital signature with MD5 digest",
		"Certificate is signed using RSA digital signature with SHA1 diges",
		"Certificate contains a DSA key",
		"Certificate is signed using DSA digital signature with SHA1 digest",
		"Certificate contains a DH key",
		"Certificate is signed using RSA digital signature with SHA-224 digest",
		"Certificate is signed using RSA digital signature with SHA-256 digest",
		"Certificate is signed using RSA digital signature with SHA-384 digest",
		"Certificate is signed using RSA digital signature with SHA-256 digest",
		"Certificate contains an RSA key, which can be used only in RSA-PSS signature scheme",
		"Certificate contains an RSA key, which can be used only for RSA-OAEP encryption",
		"Certificate is signed using PCA digital signature with RIPEMD-160 digest"
		);	
	
	this.info.PublicKeyAlgorithm = "The algorithm is unknown";
	
	if((this.ssh.PublicKeyAlgorithm >= 0) && (arrayPublicKeyAlgorithm.length > this.ssh.PublicKeyAlgorithm))
		this.info.PublicKeyAlgorithm = arrayPublicKeyAlgorithm[this.ssh.PublicKeyAlgorithm];
	
	return(this.info);	
}
classSSH.prototype.Login = function(strUser, strPass, boolCloseOnExit)
{
	this.ssh.User = strUser;
	this.ssh.Pass = strPass;
	boolCloseOnExit = (boolCloseOnExit == null) ? false : boolCloseOnExit;
	
	this.ssh.Connect();
	
	if (this.ssh.ServerKeyFingerprint.length == 0) 
	{
		trace(this.ssh.LastError);
		if( boolCloseOnExit && this.ssh.Active)
			this.ssh.Close();
		return (-1);
	}
	
	if(this.ssh.LoggedIn)
	{
		if( boolCloseOnExit && this.ssh.Active)
			this.ssh.Close();
		return(1);
	}
	
	if(this.ssh.LastError.length > 0)
		trace(this.ssh.LastError);
	
	if( boolCloseOnExit && this.ssh.Active)
		this.ssh.Close();
		
	return(0);
	
}