#include "classSSLCertificate.inc";
//#include "string_helpers.inc";
//#include "debug_helpers.inc";
function debug(strValue)
{
	trace(strValue);
}
function classSSL(strHost)
{
	this.socket = new TSocket('tcp');
	this.strHost = strHost;
	this.sslInfo = new Object();
	
	this.socket.host = strHost;
	this.socket.timeout = 4;
	
	this.testedForCRIME = false;	
	this.testedForPublicKeyLength = false;
	
	//Cipher suites.
	//nb: key names should start with one of "SSL2_", "SSL3_", or "TLS1".
	var ciphers = new Array();
	var ciphersDescription = new Array(); 
	
	//SSLv2
	//from OpenSSL's ssl2.h
	ciphers["SSL2_CK_NULL_WITH_MD5"]                    = strFromRawData(0x00, 0x00, 0x00);
	ciphers["SSL2_CK_RC4_128_WITH_MD5"]                 = strFromRawData(0x01, 0x00, 0x80);
	ciphers["SSL2_CK_RC4_128_EXPORT40_WITH_MD5"]        = strFromRawData (0x02, 0x00, 0x80);
	ciphers["SSL2_CK_RC2_128_CBC_WITH_MD5"]             = strFromRawData(0x03, 0x00, 0x80);
	ciphers["SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5"]    = strFromRawData(0x04, 0x00, 0x80);
	ciphers["SSL2_CK_IDEA_128_CBC_WITH_MD5"]            = strFromRawData(0x05, 0x00, 0x80);
	ciphers["SSL2_CK_DES_64_CBC_WITH_MD5"]              = strFromRawData(0x06, 0x00, 0x40);
	ciphers["SSL2_CK_DES_64_CBC_WITH_SHA"]              = strFromRawData(0x06, 0x01, 0x40);
	ciphers["SSL2_CK_DES_192_EDE3_CBC_WITH_MD5"]        = strFromRawData(0x07, 0x00, 0xc0);
	ciphers["SSL2_CK_DES_192_EDE3_CBC_WITH_SHA"]        = strFromRawData(0x07, 0x01, 0xc0);
	ciphers["SSL2_CK_RC4_64_WITH_MD5"]                  = strFromRawData(0x08, 0x00, 0x80);
	ciphers["SSL2_CK_DES_64_CFB64_WITH_MD5_1"]          = strFromRawData(0xff, 0x08, 0x00);
	ciphers["SSL2_CK_NULL"]                             = strFromRawData(0xff, 0x08, 0x10);
	//SSLv3
	//from OpenSSL's ssl3.h
	ciphers["SSL3_CK_RSA_NULL_MD5"]                     = strFromRawData(0x00, 0x01);
	ciphers["SSL3_CK_RSA_NULL_SHA"]                     = strFromRawData(0x00, 0x02);
	ciphers["SSL3_CK_RSA_RC4_40_MD5"]                   = strFromRawData(0x00, 0x03);
	ciphers["SSL3_CK_RSA_RC4_128_MD5"]                  = strFromRawData(0x00, 0x04);
	ciphers["SSL3_CK_RSA_RC4_128_SHA"]                  = strFromRawData(0x00, 0x05);
	ciphers["SSL3_CK_RSA_RC2_40_MD5"]                   = strFromRawData(0x00, 0x06);
	ciphers["SSL3_CK_RSA_IDEA_128_SHA"]                 = strFromRawData(0x00, 0x07);
	ciphers["SSL3_CK_RSA_DES_40_CBC_SHA"]               = strFromRawData(0x00, 0x08);
	ciphers["SSL3_CK_RSA_DES_64_CBC_SHA"]               = strFromRawData(0x00, 0x09);
	ciphers["SSL3_CK_RSA_DES_192_CBC3_SHA"]             = strFromRawData(0x00, 0x0A);
	ciphers["SSL3_CK_DH_DSS_DES_40_CBC_SHA"]            = strFromRawData(0x00, 0x0B);
	ciphers["SSL3_CK_DH_DSS_DES_64_CBC_SHA"]            = strFromRawData(0x00, 0x0C);
	ciphers["SSL3_CK_DH_DSS_DES_192_CBC3_SHA"]          = strFromRawData(0x00, 0x0D);
	ciphers["SSL3_CK_DH_RSA_DES_40_CBC_SHA"]            = strFromRawData(0x00, 0x0E);
	ciphers["SSL3_CK_DH_RSA_DES_64_CBC_SHA"]            = strFromRawData(0x00, 0x0F);
	ciphers["SSL3_CK_DH_RSA_DES_192_CBC3_SHA"]          = strFromRawData(0x00, 0x10);
	ciphers["SSL3_CK_EDH_DSS_DES_40_CBC_SHA"]           = strFromRawData(0x00, 0x11);
	ciphers["SSL3_CK_EDH_DSS_DES_64_CBC_SHA"]           = strFromRawData(0x00, 0x12);
	ciphers["SSL3_CK_EDH_DSS_DES_192_CBC3_SHA"]         = strFromRawData(0x00, 0x13);
	ciphers["SSL3_CK_EDH_RSA_DES_40_CBC_SHA"]           = strFromRawData(0x00, 0x14);
	ciphers["SSL3_CK_EDH_RSA_DES_64_CBC_SHA"]           = strFromRawData(0x00, 0x15);
	ciphers["SSL3_CK_EDH_RSA_DES_192_CBC3_SHA"]         = strFromRawData(0x00, 0x16);
	ciphers["SSL3_CK_ADH_RC4_40_MD5"]                   = strFromRawData(0x00, 0x17);
	ciphers["SSL3_CK_ADH_RC4_128_MD5"]                  = strFromRawData(0x00, 0x18);
	ciphers["SSL3_CK_ADH_DES_40_CBC_SHA"]               = strFromRawData(0x00, 0x19);
	ciphers["SSL3_CK_ADH_DES_64_CBC_SHA"]               = strFromRawData(0x00, 0x1A);
	ciphers["SSL3_CK_ADH_DES_192_CBC_SHA"]              = strFromRawData(0x00, 0x1B);
	ciphers["SSL3_CK_FZA_DMS_NULL_SHA"]                 = strFromRawData(0x00, 0x1C);
	ciphers["SSL3_CK_FZA_DMS_FZA_SHA"]                  = strFromRawData(0x00, 0x1D);
	ciphers["SSL3_CK_KRB5_DES_64_CBC_SHA"]              = strFromRawData(0x00, 0x1E);
	ciphers["SSL3_CK_KRB5_DES_192_CBC3_SHA"]            = strFromRawData(0x00, 0x1F);
	ciphers["SSL3_CK_KRB5_RC4_128_SHA"]                 = strFromRawData(0x00, 0x20);
	ciphers["SSL3_CK_KRB5_IDEA_128_CBC_SHA"]            = strFromRawData(0x00, 0x21);
	ciphers["SSL3_CK_KRB5_DES_64_CBC_MD5"]              = strFromRawData(0x00, 0x22);
	ciphers["SSL3_CK_KRB5_DES_192_CBC3_MD5"]            = strFromRawData(0x00, 0x23);
	ciphers["SSL3_CK_KRB5_RC4_128_MD5"]                 = strFromRawData(0x00, 0x24);
	ciphers["SSL3_CK_KRB5_IDEA_128_CBC_MD5"]            = strFromRawData(0x00, 0x25);
	ciphers["SSL3_CK_KRB5_DES_40_CBC_SHA"]              = strFromRawData(0x00, 0x26);
	ciphers["SSL3_CK_KRB5_RC2_40_CBC_SHA"]              = strFromRawData(0x00, 0x27);
	ciphers["SSL3_CK_KRB5_RC4_40_SHA"]                  = strFromRawData(0x00, 0x28);
	ciphers["SSL3_CK_KRB5_DES_40_CBC_MD5"]              = strFromRawData(0x00, 0x29);
	ciphers["SSL3_CK_KRB5_RC2_40_CBC_MD5"]              = strFromRawData(0x00, 0x2A);
	ciphers["SSL3_CK_KRB5_RC4_40_MD5"]                  = strFromRawData(0x00, 0x2B);
	//TLSv1
	//-   from http://www.iana.org/assignments/tls-parameters
	ciphers["TLS1_CK_NULL_WITH_NULL_NULL"]              = strFromRawData(0x00, 0x00);
	ciphers["TLS1_CK_RSA_WITH_NULL_MD5"]                = strFromRawData(0x00, 0x01);
	ciphers["TLS1_CK_RSA_WITH_NULL_SHA"]                = strFromRawData(0x00, 0x02);
	ciphers["TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5"]       = strFromRawData(0x00, 0x03);
	ciphers["TLS1_CK_RSA_WITH_RC4_128_MD5"]             = strFromRawData(0x00, 0x04);
	ciphers["TLS1_CK_RSA_WITH_RC4_128_SHA"]             = strFromRawData(0x00, 0x05);
	ciphers["TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5"]   = strFromRawData(0x00, 0x06);
	ciphers["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"]            = strFromRawData(0x00, 0x07);
	ciphers["TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA"]    = strFromRawData(0x00, 0x08);
	ciphers["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"]        = strFromRawData(0x00, 0x0A);
	ciphers["TLS1_CK_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"] = strFromRawData(0x00, 0x0B);
	ciphers["TLS1_CK_DH_DSS_WITH_DES_CBC_SHA"]          = strFromRawData(0x00, 0x0C);
	ciphers["TLS1_CK_DH_DSS_WITH_3DES_EDE_CBC_SHA"]     = strFromRawData(0x00, 0x0D);
	ciphers["TLS1_CK_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] = strFromRawData(0x00, 0x0E);
	ciphers["TLS1_CK_DH_RSA_WITH_DES_CBC_SHA"]          = strFromRawData(0x00, 0x0F);
	ciphers["TLS1_CK_DH_RSA_WITH_3DES_EDE_CBC_SHA"]     = strFromRawData(0x00, 0x10);
	ciphers["TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"]= strFromRawData(0x00, 0x11);
	ciphers["TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA"]         = strFromRawData(0x00, 0x12);
	ciphers["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"]    = strFromRawData(0x00, 0x13);
	ciphers["TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"]= strFromRawData(0x00, 0x14);
	ciphers["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"]    = strFromRawData(0x00, 0x16);
	ciphers["TLS1_CK_DH_anon_EXPORT_WITH_RC4_40_MD5"]   = strFromRawData(0x00, 0x17);
	ciphers["TLS1_CK_DH_anon_WITH_RC4_128_MD5"]         = strFromRawData(0x00, 0x18);
	ciphers["TLS1_CK_DH_anon_EXPORT_WITH_DES40_CBC_SHA"]= strFromRawData(0x00, 0x19);
	ciphers["TLS1_CK_DH_anon_WITH_DES_CBC_SHA"]         = strFromRawData(0x00, 0x1A);
	ciphers["TLS1_CK_DH_anon_WITH_3DES_EDE_CBC_SHA"]    = strFromRawData(0x00, 0x1B);
	ciphers["TLS1_CK_KRB5_WITH_DES_CBC_SHA"]            = strFromRawData(0x00, 0x1E);
	ciphers["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_SHA"]       = strFromRawData(0x00, 0x1F);
	ciphers["TLS1_CK_KRB5_WITH_RC4_128_SHA"]            = strFromRawData(0x00, 0x20);
	ciphers["TLS1_CK_KRB5_WITH_IDEA_CBC_SHA"]           = strFromRawData(0x00, 0x21);
	ciphers["TLS1_CK_KRB5_WITH_DES_CBC_MD5"]            = strFromRawData(0x00, 0x22);
	ciphers["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_MD5"]       = strFromRawData(0x00, 0x23);
	ciphers["TLS1_CK_KRB5_WITH_RC4_128_MD5"]            = strFromRawData(0x00, 0x24);
	ciphers["TLS1_CK_KRB5_WITH_IDEA_CBC_MD5"]           = strFromRawData(0x00, 0x25);
	ciphers["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_SHA"]  = strFromRawData(0x00, 0x26);
	ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"]  = strFromRawData(0x00, 0x27);
	ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_SHA"]      = strFromRawData(0x00, 0x28);
	ciphers["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_MD5"]  = strFromRawData(0x00, 0x29);
	ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"]  = strFromRawData(0x00, 0x2A);
	ciphers["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_MD5"]      = strFromRawData(0x00, 0x2B);
	ciphers["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"]         = strFromRawData(0x00, 0x2F);
	ciphers["TLS1_CK_DH_DSS_WITH_AES_128_CBC_SHA"]      = strFromRawData(0x00, 0x30);
	ciphers["TLS1_CK_DH_RSA_WITH_AES_128_CBC_SHA"]      = strFromRawData(0x00, 0x31);
	ciphers["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"]     = strFromRawData(0x00, 0x32);
	ciphers["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"]     = strFromRawData(0x00, 0x33);
	ciphers["TLS1_CK_DH_anon_WITH_AES_128_CBC_SHA"]     = strFromRawData(0x00, 0x34);
	ciphers["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"]         = strFromRawData(0x00, 0x35);
	ciphers["TLS1_CK_DH_DSS_WITH_AES_256_CBC_SHA"]      = strFromRawData(0x00, 0x36);
	ciphers["TLS1_CK_DH_RSA_WITH_AES_256_CBC_SHA"]      = strFromRawData(0x00, 0x37);
	ciphers["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"]     = strFromRawData(0x00, 0x38);
	ciphers["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"]     = strFromRawData(0x00, 0x39);
	ciphers["TLS1_CK_DH_anon_WITH_AES_256_CBC_SHA"]     = strFromRawData(0x00, 0x3A);
	//  nb: these aren't part of the IANA spec but are supported by OpenSSL
	//        if TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES is defined.
	ciphers["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5"]   = strFromRawData(0x00, 0x60);
	ciphers["TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"]= strFromRawData(0x00, 0x61);
	ciphers["TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA"]  = strFromRawData(0x00, 0x62);
	ciphers["TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"]= strFromRawData(0x00, 0x63);
	ciphers["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA"]   = strFromRawData(0x00, 0x64);
	ciphers["TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"]= strFromRawData(0x00, 0x65);
	ciphers["TLS1_CK_DHE_DSS_WITH_RC4_128_SHA"]         = strFromRawData(0x00, 0x66);
	//-   nb: Camellia, from RFC 4132
	ciphers["TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA"]    = strFromRawData(0x00, 0x41);
	ciphers["TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] = strFromRawData(0x00, 0x42);
	ciphers["TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] = strFromRawData(0x00, 0x43);
	ciphers["TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"]= strFromRawData(0x00, 0x44);
	ciphers["TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"]= strFromRawData(0x00, 0x45);
	ciphers["TLS1_CK_DH_anon_WITH_CAMELLIA_128_CBC_SHA"]= strFromRawData(0x00, 0x46);
	ciphers["TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA"]    = strFromRawData(0x00, 0x84);
	ciphers["TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] = strFromRawData(0x00, 0x85);
	ciphers["TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] = strFromRawData(0x00, 0x86);
	ciphers["TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"]= strFromRawData(0x00, 0x87);
	ciphers["TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"]= strFromRawData(0x00, 0x88);
	ciphers["TLS1_CK_DH_anon_WITH_CAMELLIA_256_CBC_SHA"]= strFromRawData(0x00, 0x89);
	//-   nb: TLS w/ pre-shared keys, RFC 4279.
	ciphers["TLS1_CK_PSK_WITH_RC4_128_SHA"]             = strFromRawData(0x00, 0x8A);
	ciphers["TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA"]        = strFromRawData(0x00, 0x8B);
	ciphers["TLS1_CK_PSK_WITH_AES_128_CBC_SHA"]         = strFromRawData(0x00, 0x8C);
	ciphers["TLS1_CK_PSK_WITH_AES_256_CBC_SHA"]         = strFromRawData(0x00, 0x8D);
	ciphers["TLS1_CK_DHE_PSK_WITH_RC4_128_SHA"]         = strFromRawData(0x00, 0x8E);
	ciphers["TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA"]    = strFromRawData(0x00, 0x8F);
	ciphers["TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA"]     = strFromRawData(0x00, 0x90);
	ciphers["TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA"]     = strFromRawData(0x00, 0x91);
	ciphers["TLS1_CK_RSA_PSK_WITH_RC4_128_SHA"]         = strFromRawData(0x00, 0x92);
	ciphers["TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA"]    = strFromRawData(0x00, 0x93);
	ciphers["TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA"]     = strFromRawData(0x00, 0x94);
	ciphers["TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA"]     = strFromRawData(0x00, 0x95);
	//-   nb: SEED Cipher Suites, RFC 4162.
	ciphers["TLS1_CK_RSA_WITH_SEED_CBC_SHA"]            = strFromRawData(0x00, 0x96);
	ciphers["TLS1_CK_DH_DSS_WITH_SEED_CBC_SHA"]         = strFromRawData(0x00, 0x97);
	ciphers["TLS1_CK_DH_RSA_WITH_SEED_CBC_SHA"]         = strFromRawData(0x00, 0x98);
	ciphers["TLS1_CK_DHE_DSS_WITH_SEED_CBC_SHA"]        = strFromRawData(0x00, 0x99);
	ciphers["TLS1_CK_DHE_RSA_WITH_SEED_CBC_SHA"]        = strFromRawData(0x00, 0x9A);
	ciphers["TLS1_CK_DH_anon_WITH_SEED_CBC_SHA"]        = strFromRawData(0x00, 0x9B);
	//-   nb: Elliptic Curve Cryptography (ECC) Cipher Suites, RFC 4492
	ciphers["TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA"]         = strFromRawData(0xC0, 0x01);
	ciphers["TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA"]      = strFromRawData(0xC0, 0x02);
	ciphers["TLS1_CK_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = strFromRawData(0xC0, 0x03);
	ciphers["TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA"]  = strFromRawData(0xC0, 0x04);
	ciphers["TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA"]  = strFromRawData(0xC0, 0x05);
	ciphers["TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA"]        = strFromRawData(0xC0, 0x06);
	ciphers["TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA"]     = strFromRawData(0xC0, 0x07);
	ciphers["TLS1_CK_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"]= strFromRawData(0xC0, 0x08);
	ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] = strFromRawData(0xC0, 0x09);
	ciphers["TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = strFromRawData(0xC0, 0x0A);
	ciphers["TLS1_CK_ECDH_RSA_WITH_NULL_SHA"]           = strFromRawData(0xC0, 0x0B);
	ciphers["TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA"]        = strFromRawData(0xC0, 0x0C);
	ciphers["TLS1_CK_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"]   = strFromRawData(0xC0, 0x0D);
	ciphers["TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA"]    = strFromRawData(0xC0, 0x0E);
	ciphers["TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA"]    = strFromRawData(0xC0, 0x0F);
	ciphers["TLS1_CK_ECDHE_RSA_WITH_NULL_SHA"]          = strFromRawData(0xC0, 0x10);
	ciphers["TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA"]       = strFromRawData(0xC0, 0x11);
	ciphers["TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"]  = strFromRawData(0xC0, 0x12);
	ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"]   = strFromRawData(0xC0, 0x13);
	ciphers["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"]   = strFromRawData(0xC0, 0x14);
	ciphers["TLS1_CK_ECDH_anon_NULL_WITH_SHA"]          = strFromRawData(0xC0, 0x15);
	ciphers["TLS1_CK_ECDH_anon_WITH_RC4_128_SHA"]       = strFromRawData(0xC0, 0x16);
	ciphers["TLS1_CK_ECDH_anon_WITH_3DES_EDE_CBC_SHA"]  = strFromRawData(0xC0, 0x17);
	ciphers["TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA"]   = strFromRawData(0xC0, 0x18);
	ciphers["TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA"]   = strFromRawData(0xC0, 0x19);
	
	
	ciphersDescription["SSL2_CK_NULL_WITH_MD5"]                    = "OpenSSL ciphername: NULL-MD5, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: None, Message authentication code: MD5";
	ciphersDescription["SSL2_CK_RC4_128_WITH_MD5"]                 = "OpenSSL ciphername: RC4-MD5, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: RC4(128), Message authentication code: MD5";
	ciphersDescription["SSL2_CK_RC4_128_EXPORT40_WITH_MD5"]        = "OpenSSL ciphername: EXP-RC4-MD5, Protocol version: SSLv2, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: RC4(40), Message authentication code: MD5, export";
	ciphersDescription["SSL2_CK_RC2_128_CBC_WITH_MD5"]             = "OpenSSL ciphername: RC2-CBC-MD5, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: RC2(128), Message authentication code: MD5";
	ciphersDescription["SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5"]    = "OpenSSL ciphername: EXP-RC2-CBC-MD5, Protocol version: SSLv2, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: RC2(40), Message authentication code: MD5, export";
	ciphersDescription["SSL2_CK_IDEA_128_CBC_WITH_MD5"]            = "OpenSSL ciphername: OpenSSL ciphername: IDEA-CBC-MD5, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: IDEA(128), Message authentication code: MD5";
	ciphersDescription["SSL2_CK_DES_64_CBC_WITH_MD5"]              = "OpenSSL ciphername: DES-CBC-MD5, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: MD5";
	ciphersDescription["SSL2_CK_DES_64_CBC_WITH_SHA"]              = "OpenSSL ciphername: DES-CBC-SHA, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL2_CK_DES_192_EDE3_CBC_WITH_MD5"]        = "OpenSSL ciphername: DES-CBC3-MD5, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: MD5";
	ciphersDescription["SSL2_CK_DES_192_EDE3_CBC_WITH_SHA"]        = "OpenSSL ciphername: DES-CBC3-SHA, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL2_CK_RC4_64_WITH_MD5"]                  = "OpenSSL ciphername: RC4-64-MD5, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: RC4(64), Message authentication code: MD5";
	ciphersDescription["SSL2_CK_DES_64_CFB64_WITH_MD5_1"]          = "OpenSSL ciphername: DES-CFB-M1, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: MD5 with 1 byte";
	ciphersDescription["SSL2_CK_NULL"]                             = "OpenSSL ciphername: NULL, Protocol version: SSLv2, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: None, Message authentication code: None";
	ciphersDescription["SSL3_CK_RSA_NULL_MD5"]                     = "OpenSSL ciphername: NULL-MD5, Protocol version: SSLv3, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: None, Message authentication code: MD5";
	ciphersDescription["SSL3_CK_RSA_NULL_SHA"]                     = "OpenSSL ciphername: NULL-SHA, Protocol version: SSLv3, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_RSA_RC4_40_MD5"]                   = "OpenSSL ciphername: EXP-RC4-MD5, Protocol version: SSLv3, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: RC4(40), Message authentication code: MD5, export";
	ciphersDescription["SSL3_CK_RSA_RC4_128_MD5"]                  = "OpenSSL ciphername: RC4-MD5, Protocol version: SSLv3, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: RC4(128), Message authentication code: MD5";
	ciphersDescription["SSL3_CK_RSA_RC4_128_SHA"]                  = "OpenSSL ciphername: RC4-SHA, Protocol version: SSLv3, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_RSA_RC2_40_MD5"]                   = "OpenSSL ciphername: EXP-RC2-CBC-MD5, Protocol version: SSLv3, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: RC2(40), Message authentication code: MD5, export";
	ciphersDescription["SSL3_CK_RSA_IDEA_128_SHA"]                 = "OpenSSL ciphername: IDEA-CBC-SHA, Protocol version: SSLv3, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: IDEA(128), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_RSA_DES_40_CBC_SHA"]               = "OpenSSL ciphername: EXP-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_RSA_DES_64_CBC_SHA"]               = "OpenSSL ciphername: DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_RSA_DES_192_CBC3_SHA"]             = "OpenSSL ciphername: DES-CBC3-SHA, Protocol version: SSLv3, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_DH_DSS_DES_40_CBC_SHA"]            = "OpenSSL ciphername: EXP-DH-DSS-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH(512), Autentication: DSS, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_DH_DSS_DES_64_CBC_SHA"]            = "OpenSSL ciphername: DH-DSS-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_DH_DSS_DES_192_CBC3_SHA"]          = "OpenSSL ciphername: DH-DSS-DES-CBC3-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_DH_RSA_DES_40_CBC_SHA"]            = "OpenSSL ciphername: EXP-DH-RSA-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH(512), Autentication: RSA, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_DH_RSA_DES_64_CBC_SHA"]            = "OpenSSL ciphername: DH-RSA-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_DH_RSA_DES_192_CBC3_SHA"]          = "OpenSSL ciphername: DH-RSA-DES-CBC3-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_EDH_DSS_DES_40_CBC_SHA"]           = "OpenSSL ciphername: EXP-EDH-DSS-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH(512), Autentication: DSS, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_EDH_DSS_DES_64_CBC_SHA"]           = "OpenSSL ciphername: EDH-DSS-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_EDH_DSS_DES_192_CBC3_SHA"]         = "OpenSSL ciphername: EDH-DSS-DES-CBC3-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_EDH_RSA_DES_40_CBC_SHA"]           = "OpenSSL ciphername: EXP-EDH-RSA-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH(512), Autentication: RSA, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_EDH_RSA_DES_64_CBC_SHA"]           = "OpenSSL ciphername: EDH-RSA-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_EDH_RSA_DES_192_CBC3_SHA"]         = "OpenSSL ciphername: EDH-RSA-DES-CBC3-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_ADH_RC4_40_MD5"]                   = "OpenSSL ciphername: EXP-ADH-RC4-MD5, Protocol version: SSLv3, Key Exchange: DH(512), Autentication: None, Symmetric encryption method: RC4(40), Message authentication code: MD5, export";
	ciphersDescription["SSL3_CK_ADH_RC4_128_MD5"]                  = "OpenSSL ciphername: ADH-RC4-MD5, Protocol version: SSLv3, Key Exchange: DH, Autentication: None, Symmetric encryption method: RC4(128), Message authentication code: MD5";
	ciphersDescription["SSL3_CK_ADH_DES_40_CBC_SHA"]               = "OpenSSL ciphername: EXP-ADH-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH(512), Autentication: None, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_ADH_DES_64_CBC_SHA"]               = "OpenSSL ciphername: ADH-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: None, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_ADH_DES_192_CBC_SHA"]              = "OpenSSL ciphername: ADH-DES-CBC3-SHA, Protocol version: SSLv3, Key Exchange: DH, Autentication: None, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_FZA_DMS_NULL_SHA"]                 = "OpenSSL ciphername: FZA-NULL-SHA, Protocol version: SSLv3, Key Exchange: KEA, Autentication: DSA, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_FZA_DMS_FZA_SHA"]                  = "OpenSSL ciphername: FZA-FZA-CBC-SHA, Protocol version: SSLv3, Key Exchange: KEA, Autentication: DSA, Symmetric encryption method: SKIPJACK(80), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_KRB5_DES_64_CBC_SHA"]              = "OpenSSL ciphername: KRB5-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_KRB5_DES_192_CBC3_SHA"]            = "OpenSSL ciphername: KRB5-DES-CBC3-SHA, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_KRB5_RC4_128_SHA"]                 = "OpenSSL ciphername: KRB5-RC4-SHA, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_KRB5_IDEA_128_CBC_SHA"]            = "OpenSSL ciphername: KRB5-IDEA-CBC-SHA, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: IDEA(128), Message authentication code: SHA1";
	ciphersDescription["SSL3_CK_KRB5_DES_64_CBC_MD5"]              = "OpenSSL ciphername: KRB5-DES-CBC-MD5, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(56), Message authentication code: MD5";
	ciphersDescription["SSL3_CK_KRB5_DES_192_CBC3_MD5"]            = "OpenSSL ciphername: KRB5-DES-CBC3-MD5, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: 3DES(168), Message authentication code: MD5";
	ciphersDescription["SSL3_CK_KRB5_RC4_128_MD5"]                 = "OpenSSL ciphername: KRB5-RC4-MD5, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(128), Message authentication code: MD5";
	ciphersDescription["SSL3_CK_KRB5_IDEA_128_CBC_MD5"]            = "OpenSSL ciphername: KRB5-IDEA-CBC-MD5, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: IDEA(128), Message authentication code: MD5";
	ciphersDescription["SSL3_CK_KRB5_DES_40_CBC_SHA"]              = "OpenSSL ciphername: EXP-KRB5-DES-CBC-SHA, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_KRB5_RC2_40_CBC_SHA"]              = "OpenSSL ciphername: EXP-KRB5-RC2-CBC-SHA, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC2(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_KRB5_RC4_40_SHA"]                  = "OpenSSL ciphername: EXP-KRB5-RC4-SHA, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(40), Message authentication code: SHA1, export";
	ciphersDescription["SSL3_CK_KRB5_DES_40_CBC_MD5"]              = "OpenSSL ciphername: EXP-KRB5-DES-CBC-MD5, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(40), Message authentication code: MD5, export";
	ciphersDescription["SSL3_CK_KRB5_RC2_40_CBC_MD5"]              = "OpenSSL ciphername: EXP-KRB5-RC2-CBC-MD5, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC2(40), Message authentication code: MD5, export";
	ciphersDescription["SSL3_CK_KRB5_RC4_40_MD5"]                  = "OpenSSL ciphername: EXP-KRB5-RC4-MD5, Protocol version: SSLv3, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(40), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_NULL_WITH_NULL_NULL"]              = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: None, Autentication: None, Symmetric encryption method: None, Message authentication code: None";
	ciphersDescription["TLS1_CK_RSA_WITH_NULL_MD5"]                = "OpenSSL ciphername: NULL-MD5, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: None, Message authentication code: MD5";
	ciphersDescription["TLS1_CK_RSA_WITH_NULL_SHA"]                = "OpenSSL ciphername: NULL-SHA, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5"]       = "OpenSSL ciphername: EXP-RC4-MD5, Protocol version: TLSv1, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: RC4(40), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_RSA_WITH_RC4_128_MD5"]             = "OpenSSL ciphername: RC4-MD5, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: RC4(128), Message authentication code: MD5";
	ciphersDescription["TLS1_CK_RSA_WITH_RC4_128_SHA"]             = "OpenSSL ciphername: RC4-SHA, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5"]   = "OpenSSL ciphername: EXP-RC2-CBC-MD5, Protocol version: TLSv1, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: RC2(40), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"]            = "OpenSSL ciphername: IDEA-CBC-SHA, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: IDEA(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA"]    = "OpenSSL ciphername: EXP-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: RSA(512), Autentication: RSA, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"]        = "OpenSSL ciphername: DES-CBC3-SHA, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"] = "OpenSSL ciphername: EXP-DH-DSS-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH(512), Autentication: DSS, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DH_DSS_WITH_DES_CBC_SHA"]          = "OpenSSL ciphername: DH-DSS-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_DSS_WITH_3DES_EDE_CBC_SHA"]     = "OpenSSL ciphername: DH-DSS-DES-CBC3-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"] = "OpenSSL ciphername: EXP-DH-RSA-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH(512), Autentication: RSA, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DH_RSA_WITH_DES_CBC_SHA"]          = "OpenSSL ciphername: DH-RSA-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_RSA_WITH_3DES_EDE_CBC_SHA"]     = "OpenSSL ciphername: DH-RSA-DES-CBC3-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"]= "OpenSSL ciphername: EXP-EDH-DSS-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH(512), Autentication: DSS, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA"]         = "OpenSSL ciphername: EDH-DSS-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"]    = "OpenSSL ciphername: EDH-DSS-DES-CBC3-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"]= "OpenSSL ciphername: EXP-EDH-RSA-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH(512), Autentication: RSA, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"]    = "OpenSSL ciphername: EDH-RSA-DES-CBC3-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_anon_EXPORT_WITH_RC4_40_MD5"]   = "OpenSSL ciphername: EXP-ADH-RC4-MD5, Protocol version: TLSv1, Key Exchange: DH(512), Autentication: None, Symmetric encryption method: RC4(40), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_DH_anon_WITH_RC4_128_MD5"]         = "OpenSSL ciphername: ADH-RC4-MD5, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: RC4(128), Message authentication code: MD5";
	ciphersDescription["TLS1_CK_DH_anon_EXPORT_WITH_DES40_CBC_SHA"]= "OpenSSL ciphername: EXP-ADH-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH(512), Autentication: None, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DH_anon_WITH_DES_CBC_SHA"]         = "OpenSSL ciphername: ADH-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_anon_WITH_3DES_EDE_CBC_SHA"]    = "OpenSSL ciphername: ADH-DES-CBC3-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_KRB5_WITH_DES_CBC_SHA"]            = "OpenSSL ciphername: KRB5-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(56), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_SHA"]       = "OpenSSL ciphername: KRB5-DES-CBC3-SHA, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_KRB5_WITH_RC4_128_SHA"]            = "OpenSSL ciphername: KRB5-RC4-SHA, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_KRB5_WITH_IDEA_CBC_SHA"]           = "OpenSSL ciphername: KRB5-IDEA-CBC-SHA, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: IDEA(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_KRB5_WITH_DES_CBC_MD5"]            = "OpenSSL ciphername: KRB5-DES-CBC-MD5, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(56), Message authentication code: MD5";
	ciphersDescription["TLS1_CK_KRB5_WITH_3DES_EDE_CBC_MD5"]       = "OpenSSL ciphername: KRB5-DES-CBC3-MD5, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: 3DES(168), Message authentication code: MD5";
	ciphersDescription["TLS1_CK_KRB5_WITH_RC4_128_MD5"]            = "OpenSSL ciphername: KRB5-RC4-MD5, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(128), Message authentication code: MD5";
	ciphersDescription["TLS1_CK_KRB5_WITH_IDEA_CBC_MD5"]           = "OpenSSL ciphername: KRB5-IDEA-CBC-MD5, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: IDEA(128), Message authentication code: MD5";
	ciphersDescription["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_SHA"]  = "OpenSSL ciphername: EXP-KRB5-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"]  = "OpenSSL ciphername: EXP-KRB5-RC2-CBC-SHA, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC2(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_SHA"]      = "OpenSSL ciphername: EXP-KRB5-RC4-SHA, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(40), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_KRB5_EXPORT_WITH_DES_CBC_40_MD5"]  = "OpenSSL ciphername: EXP-KRB5-DES-CBC-MD5, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: DES(40), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"]  = "OpenSSL ciphername: EXP-KRB5-RC2-CBC-MD5, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC2(40), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_KRB5_EXPORT_WITH_RC4_40_MD5"]      = "OpenSSL ciphername: EXP-KRB5-RC4-MD5, Protocol version: TLSv1, Key Exchange: KRB5, Autentication: KRB5, Symmetric encryption method: RC4(40), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"]         = "OpenSSL ciphername: AES128-SHA, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_DSS_WITH_AES_128_CBC_SHA"]      = "OpenSSL ciphername: DH-DSS-AES128-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_RSA_WITH_AES_128_CBC_SHA"]      = "OpenSSL ciphername: DH-RSA-AES128-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"]     = "OpenSSL ciphername: DHE-DSS-AES128-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"]     = "OpenSSL ciphername: DHE-RSA-AES128-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_anon_WITH_AES_128_CBC_SHA"]     = "OpenSSL ciphername: ADH-AES128-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"]         = "OpenSSL ciphername: AES256-SHA, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_DSS_WITH_AES_256_CBC_SHA"]      = "OpenSSL ciphername: DH-DSS-AES256-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_RSA_WITH_AES_256_CBC_SHA"]      = "OpenSSL ciphername: DH-RSA-AES256-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"]     = "OpenSSL ciphername: DHE-DSS-AES256-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"]     = "OpenSSL ciphername: DHE-RSA-AES256-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_anon_WITH_AES_256_CBC_SHA"]     = "OpenSSL ciphername: ADH-AES256-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5"]   = "OpenSSL ciphername: EXP1024-RC4-MD5, Protocol version: TLSv1, Key Exchange: RSA(1024), Autentication: RSA, Symmetric encryption method: RC4(56), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"]= "OpenSSL ciphername: EXP1024-RC2-CBC-MD5, Protocol version: TLSv1, Key Exchange: RSA(1024), Autentication: RSA, Symmetric encryption method: RC2(56), Message authentication code: MD5, export";
	ciphersDescription["TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA"]  = "OpenSSL ciphername: EXP1024-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: RSA(1024), Autentication: RSA, Symmetric encryption method: DES(56), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"]= "OpenSSL ciphername: EXP1024-DHE-DSS-DES-CBC-SHA, Protocol version: TLSv1, Key Exchange: DH(1024), Autentication: DSS, Symmetric encryption method: DES(56), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA"]   = "OpenSSL ciphername: EXP1024-RC4-SHA, Protocol version: TLSv1, Key Exchange: RSA(1024), Autentication: RSA, Symmetric encryption method: RC4(56), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"]= "OpenSSL ciphername: EXP1024-DHE-DSS-RC4-SHA, Protocol version: TLSv1, Key Exchange: DH(1024), Autentication: DSS, Symmetric encryption method: RC4(56), Message authentication code: SHA1, export";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_RC4_128_SHA"]         = "OpenSSL ciphername: DHE-DSS-RC4-SHA, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA"]    = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: Camellia(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"] = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: Camellia(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"] = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: Camellia(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"]= "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: Camellia(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"]= "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: Camellia(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_anon_WITH_CAMELLIA_128_CBC_SHA"]= "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: Camellia(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA"]    = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: Camellia(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"] = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: Camellia(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"] = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: Camellia(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"]= "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: Camellia(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"]= "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: Camellia(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_anon_WITH_CAMELLIA_256_CBC_SHA"]= "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: Camellia(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_PSK_WITH_RC4_128_SHA"]             = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: PSK, Autentication: PSK, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA"]        = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: PSK, Autentication: PSK, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_PSK_WITH_AES_128_CBC_SHA"]         = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: PSK, Autentication: PSK, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_PSK_WITH_AES_256_CBC_SHA"]         = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: PSK, Autentication: PSK, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_PSK_WITH_RC4_128_SHA"]         = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: PSK, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA"]    = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: PSK, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA"]     = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: PSK, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA"]     = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: PSK, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_PSK_WITH_RC4_128_SHA"]         = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: RSA, Autentication: PSK, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA"]    = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: RSA, Autentication: PSK, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA"]     = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: RSA, Autentication: PSK, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA"]     = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: RSA, Autentication: PSK, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_RSA_WITH_SEED_CBC_SHA"]            = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: RSA, Autentication: RSA, Symmetric encryption method: SEED(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_DSS_WITH_SEED_CBC_SHA"]         = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: SEED(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_RSA_WITH_SEED_CBC_SHA"]         = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: SEED(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_DSS_WITH_SEED_CBC_SHA"]        = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: DSS, Symmetric encryption method: SEED(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DHE_RSA_WITH_SEED_CBC_SHA"]        = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: RSA, Symmetric encryption method: SEED(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_DH_anon_WITH_SEED_CBC_SHA"]        = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: DH, Autentication: None, Symmetric encryption method: SEED(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA"]         = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA"]      = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"] = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA"]  = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA"]  = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA"]        = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA"]     = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"]= "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"] = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"] = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: ECDSA, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_RSA_WITH_NULL_SHA"]           = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA"]        = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"]   = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA"]    = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA"]    = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_RSA_WITH_NULL_SHA"]          = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA"]       = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"]  = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA"]   = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA"]   = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: RSA, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_anon_NULL_WITH_SHA"]          = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: None, Symmetric encryption method: None, Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_anon_WITH_RC4_128_SHA"]       = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: None, Symmetric encryption method: RC4(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_anon_WITH_3DES_EDE_CBC_SHA"]  = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: None, Symmetric encryption method: 3DES(168), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA"]   = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: None, Symmetric encryption method: AES(128), Message authentication code: SHA1";
	ciphersDescription["TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA"]   = "OpenSSL ciphername: n/a, Protocol version: TLSv1, Key Exchange: ECDH, Autentication: None, Symmetric encryption method: AES(256), Message authentication code: SHA1";
	
	this.ciphers = ciphers;
	this.ciphersDescription = ciphersDescription;
	
}
classSSL.prototype.clientHello = function(version, v2hello, mlen, mtype, cipherspec, cspeclen, sessionid, sessionidlen, challenge, challengelen, compmeths, compmethslen) 
{
	var chello, chellolen, handshake, myhello;
	//Assign some defaults.
	//set to hello packet by default
	if( (mtype == null) || (mtype <= 0) || (version == null) ) 
		mtype = strFromRawData(0x01);
	if(version == null)
		version = strFromRawData(0x03, 0x00);
	if(v2hello == null)
		v2hello = true;
	//Generate the hello.
	// - SSLv2, whether it's explicitly SSLv2 or in v2 compatability mode.
	if (version == strFromRawData(0x00, 0x02) || v2hello == true)
	{
		//Assign other defaults.
		//ciphers.
		if(cipherspec == null) 
		{
			if( (cspeclen == null) || (cspeclen <= 0 ) )
				cipherspec = 
					this.ciphers["SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5"] +
					this.ciphers["SSL2_CK_RC4_128_EXPORT40_WITH_MD5"] +
					this.ciphers["SSL2_CK_RC4_128_WITH_MD5"] +
					this.ciphers["SSL2_CK_DES_192_EDE3_CBC_WITH_MD5"];
			else 
				//nb: fill it with random bytes.
				while (cipherspec.length < cspeclen)
					cipherspec = cipherspec + strFromRawData(Random(255));
		}
		if(cspeclen == null)
		{
			cspeclen = cipherspec.length; 
			cspeclen = strFromRawData((cspeclen >> 8) & 0xff, cspeclen & 0xff);
		}
		//session ID.
		if(sessionid == null)
		{
			if(sessionidlen) 
			{	//nb: fill it with random bytes.
				while (sessionid.length < sessionidlen) 
					sessionid = sessionid + strFromRawData(Random(255));
			}
			else 
				sessionid = "";
		}
		if(sessionidlen == null) 
		{
			sessionidlen = sessionid.length;
			sessionidlen = strFromRawData((sessionidlen >> 8) & 0xff, sessionidlen & 0xff);
		}
		//challenge.
		if(challenge == null) 
			challenge = "ACUNETIXACUNETIX";
			
		if(challengelen == null)
		{
			challengelen = challenge.length;
			challengelen = strFromRawData((challengelen >> 8) & 0xff, challengelen & 0xff);
		}
		//Assemble the message.
		//nb: 2 byte length code is used since we don't need any padding.
		handshake = mtype +
			version +
			cspeclen +
			sessionidlen +
			challengelen +
			cipherspec;
    
		if (sessionid) handshake = handshake + sessionid;
		handshake = handshake + challenge;
	
		if ( (mlen <= 0) || (mlen == null) ) mlen = handshake.length;
		myhello = strFromRawData(0x80 | (mlen >> 8), mlen & 0xff) + handshake;
	}
	//SSLv3 or TLSv1.
	else if (version == strFromRawData(0x03, 0x00) || version == strFromRawData(0x03, 0x01)) 
	{
		//Assign other defaults.
		//- ciphers.
		if(cipherspec == null)
		{
			if (cspeclen == null) 
				//nb: this is what openssl s_client uses by default.
				cipherspec = 
					this.ciphers["TLS1_CK_DHE_RSA_WITH_AES_256_CBC_SHA"] +
					this.ciphers["TLS1_CK_DHE_DSS_WITH_AES_256_CBC_SHA"] +
					this.ciphers["TLS1_CK_RSA_WITH_AES_256_CBC_SHA"] +
					this.ciphers["TLS1_CK_DHE_RSA_WITH_3DES_EDE_CBC_SHA"] +
					this.ciphers["TLS1_CK_DHE_DSS_WITH_3DES_EDE_CBC_SHA"] +
					this.ciphers["TLS1_CK_RSA_WITH_3DES_EDE_CBC_SHA"] +
					this.ciphers["TLS1_CK_DHE_RSA_WITH_AES_128_CBC_SHA"] +
					this.ciphers["TLS1_CK_DHE_DSS_WITH_AES_128_CBC_SHA"] +
					this.ciphers["TLS1_CK_RSA_WITH_AES_128_CBC_SHA"] +
					this.ciphers["TLS1_CK_RSA_WITH_IDEA_CBC_SHA"] +
					this.ciphers["TLS1_CK_RSA_WITH_RC4_128_SHA"] +
					this.ciphers["TLS1_CK_RSA_WITH_RC4_128_MD5"] +
					this.ciphers["TLS1_CK_DHE_DSS_WITH_DES_CBC_SHA"] +
					this.ciphers["TLS1_CK_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"] +
					this.ciphers["TLS1_CK_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"] +
					this.ciphers["TLS1_CK_RSA_EXPORT_WITH_DES40_CBC_SHA"] +
					this.ciphers["TLS1_CK_RSA_EXPORT_WITH_RC2_CBC_40_MD5"] +
					this.ciphers["TLS1_CK_RSA_EXPORT_WITH_RC4_40_MD5"];
			else 
				//nb: fill it with random bytes.
				while (cipherspec.length < cspeclen)
					cipherspec = cipherspec + strFromRawData(Random(255));
		}
	
		if(cspeclen == null)
		{
			cspeclen = cipherspec.length;
			cspeclen = strFromRawData((cspeclen >> 8) & 0xff, cspeclen & 0xff);
		}
		if(sessionid == null)
		{
			sessionid = "";
			if(sessionidlen)
			{
				//nb: fill out field with random bytes.
				while (sessionid.length < sessionidlen)
					sessionid = sessionid + strFromRawData(Random(255));
			}
		}
		if (sessionidlen == null)
			sessionidlen = strFromRawData(sessionid.length);
		//- challenge.
		if (challenge == null)
		{
			challenge = strHexUTCUnixTime() + "ACUNETIXACUNETIXACUNETIXACUN";
		}
		//- compression methods
		if (compmeths == null)
		{
			compmeths = strFromRawData(0x00);
			
			// blade: test for CRIME
			if (!this.testedForCRIME) {
				compmeths = strFromRawData(0x02, 0x01, 0x00);
			}		
			
			// nb: fill out field with random bytes.
			while (compmeths.length < compmethslen)
				compmeths = compmeths + strFromRawData(Random(255));
		}
		if (compmethslen == null)
			compmethslen = strFromRawData(compmeths.length);
		// prepare extensions
        var extensions = "";
        // extension [server_name]
        // type: server_name
        extensions = extensions + strFromRawData(0x00, 0x00);
        // length
        extensions = extensions + strFromWord(scanHost.length + 3 + 2, true);
        // list length
        extensions = extensions + strFromWord(scanHost.length + 3, true);
        // type
        extensions = extensions + strFromRawData(0x00);
        // length
        extensions = extensions + strFromWord(scanHost.length, true);
        // name
        extensions = extensions + scanHost;
        // extensions length
        var extensionsLength = strFromWord(extensions.length, true);
		
		//Assemble the message.
		chello = 	version +
					challenge + 
					sessionidlen + sessionid +
					cspeclen + cipherspec +
					compmethslen + compmeths +
                    extensionsLength + extensions;
		chellolen = chello.length;
		handshake = mtype +
					strFromRawData(0, (chellolen >> 8) & 0xff, chellolen & 0xff) +
					chello;
		//debug("handshake: " + handshake.toHexString());
		//debug("version: " + version.toHexString());
		//debug("challenge: " + challenge.toHexString());
		//debug("sessionidlen: " + sessionidlen.toHexString());
		//debug("sessionid: " + sessionid.toHexString());
		//debug("cspeclen: " + cspeclen.toHexString());
		if (mlen == null) mlen = handshake.length;
		myhello = 	strFromRawData(0x16) +
					version +
					strFromRawData((mlen >> 8) & 0xff, mlen & 0xff) +
					handshake;
	}
	return(myhello);
}
classSSL.prototype.getCapabilities = function(port , strType)
{
	var certificates = new Array();
	var ciphers = new Array();
	if(strType == "SSL2")
	{
		var strCiphers = "";
		var retval = false;
		
		for(var cipherIndex in this.ciphers)
		{
			if(cipherIndex.match(/^SSL2/))
				strCiphers = strCiphers + this.ciphers[cipherIndex];
		}
		return(this.getSSLData("SSL2",port, strCiphers));
	}
	if((strType == "SSL3")||(strType == "TLS1"))
	{
		boolFoundOneSupportedCipher = false;
		for(var cipherIndex in this.ciphers)
		{
			if(((strType == "SSL3") && cipherIndex.match(/^SSL3/)) || ((strType == "TLS1") && cipherIndex.match(/^TLS1/)))
			{
				strCiphers = this.ciphers[cipherIndex];
				retval = this.getSSLData(strType, port, strCiphers);	
				
				if(retval)
				{
					ciphers.push(cipherIndex);
					if(!boolFoundOneSupportedCipher)
					{
						certificates = this.sslInfo.certificates.slice();
					}
					boolFoundOneSupportedCipher = true;					
				}
			}
		}
		if(boolFoundOneSupportedCipher)
		{
			this.sslInfo.certificates = certificates.slice();
			this.sslInfo.ciphers = ciphers.slice();
			return(true);
		}
		return(false);
	}
}
classSSL.prototype.parseServerCertificate = function(buffer, intOffset, intLength)
{
	debug("Certificate: " + buffer.substring(intOffset, intOffset + intLength).toHexString());
	
	if (!this.testedForPublicKeyLength)		
	{
		this.testedForPublicKeyLength = true;
		cert = new X_509Certificate(buffer.substring(intOffset, intOffset + intLength), true);
	}	
	else
		cert = new X_509Certificate(buffer.substring(intOffset, intOffset + intLength));
	
	if(cert.boolValid)
	{
		this.sslInfo.certificates.push(cert);
		return(true);
	}
	else
		return(false);	
}
classSSL.prototype.parseServerCertificates = function(record, intOffset, intLength)
{
	var certificatesLength = record.get3ByteAt(intOffset);
	debug("certificatesLength: " + certificatesLength);
	
	intOffset = intOffset + 3;
	boolFoundOneGoodCertificate = false;
	var intMax = intOffset + intLength;
	debug("intOffset: " + intOffset);
	debug("intMax: " + intMax);
	for(var i = 0; i < 10, intOffset < intMax - 3; i++) //we parse maximum 10 certificates
	{
		debug("intOffset++: " + intOffset);
		var certificateLength = record.get3ByteAt(intOffset);
		debug("certificateLength: " + record.getStringAt(intOffset, 3).toHexString());
		debug("certificateLength: " + certificateLength);
		
		boolFoundOneGoodCertificate = boolFoundOneGoodCertificate | this.parseServerCertificate(record, intOffset + 3, certificateLength);
		
		intOffset = intOffset + certificateLength + 3;
	}	
	return(boolFoundOneGoodCertificate);
}
classSSL.prototype.getSSLData = function(sslVersion, port, cipherspec) 
{
	this.sslInfo = new Object();
	this.sslInfo.ciphers = new Array();
	this.sslInfo.type = sslVersion;
	this.sslInfo.certificates = new Array();
	var boolResult = false; 
	
	this.socket.Close();
	this.socket.Port = port;
	this.socket.timeout = 4;
	//try
	{
		if (!this.socket.Connect())
		{
			trace("getServerCertificate -> Can not connect to host: " + sslVersion + " " + port);
			return(false);
		}
	
		var clientHello, svrResponse, svrResponseLength, tmp;
		
		if (sslVersion == 'SSL2')
		{
			clientHello = this.clientHello(strFromRawData(0x00, 0x02), true, null, null, cipherspec);
			debug("clientHello SSL2: " + clientHello.toHexString());
			this.socket.Send(clientHello);
	
			for(var i = 0; i < 10; i++)
			{
	
				this.socket.timeout = 1;
				tmp = this.socket.ReceiveBytes(2);
	
				if(tmp.length != 2) 
				{
					debug("SSL Protocol reception error (1)");
					this.socket.Close();
					return(false);
				}
	
				messageLength = ((tmp.getByteAt(0) & 0x7f) << 8) | tmp.getByteAt(1);
				message = this.socket.ReceiveBytes(messageLength);
				messageType = message.getByteAt(0);
				
				if(message.length != messageLength) 
				{
					debug("SSL Protocol reception error (2)");
					this.socket.Close();
					return(false);
				}
		
				if (messageType == 4 && message.length > 14)
				{
					//Handshake message
					if (message.getByteAt(2) == 1)
					{
						//X.509 certificate
						var certificateLength = message.getWordAt(5);
						var cipherSpecLength = message.getWordAt(7);
	
						//debug('message: ' + message.toHexString());
						//debug('Supported ciphers:');
						//debug('cipherSpecLength: ' + cipherSpecLength);
						//debug('certificateLength: ' + certificateLength);
						for(var j = 0; j < cipherSpecLength; j = j + 3)
						{
							for(var cipherIndex in this.ciphers)
							{
								//debug(message.substring(11 + certificateLength + j, 11 + certificateLength + j + 3).toHexString());
								if(this.ciphers[cipherIndex] == message.substring(11 + certificateLength + j, 11 + certificateLength + j + 3))
								{
									this.sslInfo.ciphers.push(cipherIndex);
								}
							}
						}
						return (this.parseServerCertificate(message, 11, certificateLength));
					}
				}
				else
				if (messageType == 0 && message.length == 2)
				{
					this.sslInfo.errorCode = message.getWordAt(1);
					this.socket.Close();
					return(false);
				}
			}
			this.socket.Close();
			return(true);
		}
		
		if ((sslVersion == 'SSL3') || (sslVersion == 'TLS1'))
		{			
			clientHello = this.clientHello(strFromRawData(0x03, ((sslVersion == 'SSL3') ?  0x00 : 0x01)), false, null, null, cipherspec);
			debug("sent clientHello " + sslVersion + ": " + clientHello.toHexString());
			this.socket.Send(clientHello);
	
			debug("Cycling SSL3 records max 10");
			
			var boolServerHelloDone = false;
			var boolCertificateReceived = false;
			
			for (var i = 0; i < 10; i++) 
			{
				debug("SSL3 record no. " + i);
			
				tmp = this.socket.ReceiveBytes(3);
				if (tmp.length != 3) 
				{
					debug('Invalid SSL record layer data 0');
					this.socket.Close();
					return(false);
				}
				
				var protocolType = tmp.substring(1, 3);
				var cipherRegex = null; ///^SSL3/;
				if(protocolType == strFromRawData(0x03, 0x01))
					cipherRegex = /^TLS1/;
				if(protocolType == strFromRawData(0x03, 0x00))
					cipherRegex = /^SSL3/;
	
				debug("Protocol type: " + tmp.toHexString() + " = " + protocolType);
					
				var recordLength = this.socket.ReceiveBytes(2);	
				if (recordLength.length < 2) //handshake protocol
				{
					debug('Invalid SSL record layer data 1');
					this.socket.Close();
					return (false);
				}
		
				debug("Record Length: " + recordLength.toHexString() + " = " + recordLength.getWordAt(0));
	
				var record = this.socket.ReceiveBytes(recordLength.getWordAt(0));
				if(record.length != recordLength.getWordAt(0))
				{
					debug('Invalid SSL2 record layer data: invalid length.');
					this.socket.Close();
					return (false);
				}
				
				debug("Received Record: " + record.toHexString())
				debug("Received Record length: " + record.length);
	
				if(tmp.getByteAt(0) == 21) //alert
				{
					debug("ALERT received, aborting.");
					//todo: interpret the error it may not be fatal!!
					this.socket.Close();
					return(false);
				}
					
				if(tmp.getByteAt(0) != 22)
				{
					debug('This is not handshake: ' + tmp.getByteAt(0));
					continue;
				}
			
				if(cipherRegex == null)
				{
					debug('Invalid handshake SSL3/TLS1 version');
					continue;
				}
				
				var subRecordIndex = 0;
				var subRecordLength;
				var subRecordType;			
	
				debug("Start parsing the record ============================================");
	
				while (subRecordIndex < record.length) 
				{
					
					subRecordType = record.getByteAt(subRecordIndex + 0);
					subRecordLength = record.getWordAt(subRecordIndex + 2);
									
					debug("subRecordIndex: " + subRecordIndex);
					debug("subRecordType: " + subRecordType);
					debug("subRecordLength: " + subRecordLength);
					
					switch (subRecordType)
					{
						case 0x02:
						{
							debug("Server Hello: 0x02");
							
							var sessionIdAddress = subRecordIndex + 1 + 3 + 2 + 4 + 28;
							var sessionIdLength = record.getByteAt(sessionIdAddress);
	
							debug("Session ID length address: " + sessionIdAddress);
							debug("Session ID length: " + sessionIdLength);
	
							var cipherStart = subRecordIndex + 1 + 3 + 2 + 4 + 28 + 1 + sessionIdLength;							
							var cipher = record.substring(cipherStart, cipherStart + 2);
							
							// blade: test for CRIME
							if (!this.testedForCRIME) {							
								var compressionStart = cipherStart + 2;
								var compression = record.getByteAt(compressionStart);
								
								debug('compression: ' + compression);
								if (compression == 1) {
									ReportItem("crime_attack.xml", "The server accepts Deflate compression."); 
								}
								
								this.testedForCRIME = true;								
							}
							
							for (var cipherIndex in this.ciphers) 
								if ((this.ciphers[cipherIndex] == cipher) && (cipherIndex.match(cipherRegex))) 
									this.sslInfo.ciphers.push(cipherIndex);
							
							boolServerHelloDone = true;
							if(boolCertificateReceived)
							{
								this.socket.Close();
								return(true);
							}
							break;
						}
						case 12:
						{
							debug("Server Key Exchange: 12");
							break;
						}
						case 11:
						{
							debug("Certificate: 11");
							var bc = this.parseServerCertificates(record, subRecordIndex + 4, subRecordLength);
							if(!bc)
							{
								this.socket.Close();
								return(false);
							}
							boolCertificateReceived = true;
							if(boolServerHelloDone)
							{
								this.socket.Close();
								return(true);
							}
							break;
						}
						case 21:
						{
							debug("Alert: 21")
							var alertLength = record.getWordAt(subRecordIndex + 4);
							if (alertLength == 2) 
							{
								this.sslInfo.errorLevel = record.getByteAt(subRecordIndex + 5);
								this.sslInfo.errorCode = record.getByteAt(subRecordIndex + 6);
							}
							break;
						}
						case 14:
						{
							debug("Server hello done: 14");
							break;
						}
					}
					subRecordIndex = subRecordIndex + subRecordLength + 4;
				}
			}
			this.socket.Close();
			return(false);
		}
	}
	/*
	catch(error)
	{
		boolResult = false;
	}
	*/
	this.socket.Close();
	return(boolResult);
}
classSSL.prototype.checkFileForGivenHash = function(strFileName, strHash)
{
	//debug("Checking " + strHash + " in " + strFileName);
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
classSSL.prototype.checkForRandomBug = function(value)
{
	
	var retval = 0;
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_dsa_1024_keys.txt", value);
	if((! retval.error) && (retval.strLine != "")) return('DSA 1024 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_2048_keys.txt", value);
	if((! retval.error) && (retval.strLine != "")) return('RSA 2048 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_1023_keys.txt", value);
	if((! retval.error) && (retval.strLine != "")) return('RSA 1023 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_1024_keys.txt", value);
	if((! retval.error) && (retval.strLine != "")) return('RSA 1024 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_2047_keys.txt", value);
	if((! retval.error) && (retval.strLine != "")) return('RSA 2047 bit:' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_4096_keys.txt", value);
	if((! retval.error) && (retval.strLine != "")) return('RSA 4096 bit: ' + retval.strLine);
	
	retval = this.checkFileForGivenHash(GetGlobalValue("ApplicationDir") + "\\Data\\Scripts\\Includes\\SSHKeyFingerTips\\ssh_rsa_8192_keys.txt", value);
	if((! retval.error) && (retval.strLine != "")) return('RSA 8192 bit: ' + retval.strLine);
	
	return("");
		
}
/*test cases*/
/*
var strServerAddress = "localhost";
var sslServer = new classSSL(strServerAddress);
if(sslServer.getCapabilities(443, "SSL2"))
{
	trace("SSL2 supported");
	traceObject(sslServer.sslInfo);
}
if(sslServer.getCapabilities(443, "SSL3"))
{
	trace("SSL3 supported");
	traceObject(sslServer.sslInfo);
}
if(sslServer.getCapabilities(443, "TLS1"))
{
	trace("TLS1 supported");
	traceObject(sslServer.sslInfo);
}
*/
