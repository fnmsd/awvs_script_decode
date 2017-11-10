var si = getServerInfo();
var isWindows = false;
var isUnix = false;
var isUnknown = true;
var isApache = false;
var isIIS = false;
var isPHP = false;
var isNginx = false;
var islighttpd = false;
var isTomcat = false;
var isRails = false;
var isJava = false;
var isNode = false;
var si = getServerInfo();
if (si.hasTechnology('Rails')) {
    isRails = true;
}    
if (si.hasTechnology('Node.js') || si.hasTechnology('nodejs')) {
    isNode = true;
}  
if (si.hasTechnology('Java/J2EE')) {
    isJava = true;
}    
if (si.match('${Platform_OS}', 'Windows')){
	isWindows = true;
	isUnknown = false;	
    //trace('win');
} 
else 
if (si.match('${Platform_OS}', 'Unix')){
	isUnix = true;
	isUnknown = false;	
    //trace('unix');
} 
var banner = si.getValue('${WebServerBanner}');
var server = si.getValue('${WebServer}');
var poweredby = si.getValue('${X-Powered-By}');
if (poweredby == "") {poweredby = banner; }
//if (isWindows || isUnknown)
//if (isUnix || isUnknown)
// banner
if (banner.search(/(Apache-Coyote|Tomcat)/i) != -1){
	isTomcat = true;	
}
if (banner.search(/(Apache-Coyote|Servlet|GlassFish|JSP|Tomcat|Oracle-Application-Server|SunONE|Jetty|Zeus|Netscape-Enterprise|WebLogic|Sun-ONE-Web-Server|JRun|Java)/i) != -1){
	isJava = true;	
}
if (banner.search(/(Apache)/i) != -1){
	isApache = true;	
}
if (banner.search(/(Microsoft-IIS)/i) != -1){
	isIIS = true;	
}
if (banner.search(/(nginx\/)/i) != -1){
	isNginx = true;	
}
if (banner.search(/(lighttpd\/)/i) != -1){
	islighttpd = true;	
}
// server
if (server.search('IIS') != -1) {
	isIIS = true;	
}
if (server.search(/(Apache)/i) != -1){
	isApache = true;	
}
if (server.search(/(Tomcat)/i) != -1){
	isTomcat = true;	
}
// powered by
if (poweredby.search(/(PHP)/i) != -1){
	isPHP = true;	
}
if (poweredby.search(/(Express)/i) != -1){
	isNode = true;	
}
if (poweredby.search(/(Servlet|JSP)/i) != -1){
    isJava = true;
}
