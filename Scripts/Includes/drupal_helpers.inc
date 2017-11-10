// list of vulnerable modules/plugins
var files = Array(
    // module_name, get, post 
    // module name: core is used for drupal core alerts so it is always installed 
    ["videowhisper", "/index.php?q=vwrooms/logout&module=1&message=1", ""]
        
);
var plugins = new Array();
var lastJob = null;
// **************************************************************************************
function pluginIsInstalled(dir, uri){
    // core
    if(uri.endsWith("/core")) 
        return true;
    
    var res = false;
	lastJob = new THTTPJob();
	lastJob.verb = "GET";
	lastJob.url  = dir.url;
    lastJob.uri  = uri;
    
	lastJob.execute();
    
    if (!lastJob.wasError) {
        if (lastJob.responseStatus == 301 || lastJob.responseStatus == 302)
            {
                var locationStr = lastJob.response.headerValue('location');
    			if (locationStr && locationStr.indexOf(uri + "/") != -1)  
                    res = true;                
            }            
    }    
	return res;     
}
// **************************************************************************************
function detectInstalledPlugins(dir, root_path) {
    // get list of plugins
    for (var i=0; i<files.length; i++)
    	if (files[i][0]) plugins.push(files[i][0]);
    // remove duplicates
    plugins = eliminateDuplicates(plugins);
    
    // look for false positives
    var plugin_dir = root_path + "/modules/" + randStr(8);
    var bogusDir = false;
    if (pluginIsInstalled(dir, plugin_dir)) {
        bogusDir = true;
    }
    
    if (!bogusDir) {
        for (var i=0; i<plugins.length; i++){
            
            var plugin_name = plugins[i];
            var plugin_dir = root_path + "/modules/" + plugin_name;
                        
            if (pluginIsInstalled(dir, plugin_dir)) {
                trace("plugin installed " + plugin_name);
                
                // add http requests to the crawler
                for (var j=0; j<files.length; j++)
                	if (files[j][0] == plugin_name) {
                        var getData = files[j][1];
                        var postData = files[j][2];
                        
                        // add request
                        var r = new THTTPRequest();
                        var dir = getCurrentDirectory();
                        
                        r.URI = root_path + getData;        
                        
                        if (postData) {                            
                            r.Verb = 'POST';
                            r.body = postData;
                            r.addHeader('Content-Type', 'application/x-www-form-urlencoded', true);
                        } 
                        else r.Verb = 'GET';
                        
                        addHTTPRequestToCrawler(r);                              
                }                
            }           
        }
    }
}
// **************************************************************************************
function testForVulnPlugins(dir) {
    root_path = dir.fullPath;
    detectInstalledPlugins(dir, root_path);
}
