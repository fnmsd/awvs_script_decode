// ast_processor.js
// ===========================================
var debugMode = false;
// -------------------------------------------
function debug(msg) {
    if (debugMode) trace(msg);
}
// -------------------------------------------
function recursiveFindCallExpressions(item, padding){
    if (item && typeof(item) == 'object') {
        if (typeof(item.type) !== 'undefined') {
            //debug(padding + item.type);
            if (item.type == 'CallExpression') {
                processCallExpression(item);
            }
        }
        for(var key in item) {
            recursiveFindCallExpressions(item[key], padding + " ");
        }
    }
}
// -------------------------------------------
function evaluateBinaryExpression(item){
    var left = item.left;
    var right = item.right;
    var oper = item.operator;
    var leftStr = extractValue(left);
    var rightStr = extractValue(right);
    if (leftStr == "") leftStr = "1";
    if (rightStr == "") rightStr = "1";
    if (oper == "+") return leftStr + rightStr;
    else leftStr;
}
// -------------------------------------------
function getExpressionId(item) {
    var id = "";
    for(var key in item) {
        if (item[key] && typeof(item[key].type) != 'undefined' && item[key].type =='Identifier') id = id + item[key].name + ".";
    }
    // delete the last .
    if (id.length > 1) id = id.slice(0, -1);
    return id;
}
// -------------------------------------------
function extractValue(item) {
    // Literal
    if (item && typeof(item.type) != 'undefined' && item.type =='Literal') {
        return item.value;
    }
    // Object expression
    if (item && typeof(item.type) != 'undefined' && item.type =='ObjectExpression') {
        return extractPropertiesFromObjectExpression(item);
    }
    // Binary expression
    if (item && typeof(item.type) != 'undefined' && item.type =='BinaryExpression') {
        return evaluateBinaryExpression(item);
    }
    return "";
}
// -------------------------------------------
function extractIdentifierName(item) {
    var value = "";
    if (item && typeof(item.type) != 'undefined' && item.type =='Identifier') {
        value = item.name;
    }
    return value;
}
// -------------------------------------------
function convertDataObjectToString(data) {
    // object?
    if (data && typeof(data) == 'object') {
        var dataStr = "";
        for(var key in data) {
            if (data[key]) dataStr = dataStr + key + "=" + data[key] + "&";
        }
        // delete the last &
        if (dataStr.length > 1) dataStr = dataStr.slice(0, -1);
        return dataStr;
    }
    else {
        // or string
        return data;
    }
}
// -------------------------------------------
function convertDataObjectToStringJSON(data) {
    // object?
    if (data && typeof(data) == 'object') {
        var dataStr = JSON.stringify(data);
        return dataStr;
    }
    else {
        // or string
        return data;
    }
}
// -------------------------------------------
function processAjaxRequest(req) {
    if (req.method == 'GET' && req.data != "") {
        if (req.url.indexOf("&") == -1) req.url = req.url + "?" + req.data;
        else req.url = req.url + "&" + req.data;
        req.data = "";
    }
    if (req.method == 'GET' && req.contentType != "") {
        req.contentType = "";
    }
    // prepare a new HTTP request for the crawler
    var r = new THTTPRequest();
    // method
    r.verb = req.method;
    // URI
    r.URI = req.url;
    // content-type
    if (req.contentType) r.addHeader('Content-Type', req.contentType, true);
    // post data
    if (req.data) {
        r.body = req.data;
        if (!req.contentType)  r.addHeader('Content-Type', 'application/x-www-form-urlencoded', true);
    }
    r.addHeader('Host', scanUrl.hostPort, true);
    debug(r.toString());
    // send it to the crawler
    addHTTPRequestToCrawler(r);
}
// -------------------------------------------
function extractPropertiesFromObjectExpression(item) {
    var props = {}
    if (typeof(item.properties) != 'undefined') {
        for (var i=0; i<item.properties.length; i++) {
            var p = item.properties[i];
            if (p && typeof(p.type) != 'undefined' && p.type =='Property') {
                var name = extractIdentifierName(p.key);
                var value = extractValue(p.value);
                if (value == "") value = "1";
                props[name] = value;
                //debug(name + " => " + value);
            }
        }
    }
    return props;
}
// -------------------------------------------
function getObjectSize(obj) {
    var size = 0, key;
    for (key in obj) {
        size++;
    }
    return size;
}
// -------------------------------------------
function getPropertyFromObjectExpression(item, propertyName) {
    if (typeof(item.properties) != 'undefined') {
        for (var i=0; i<item.properties.length; i++) {
            var p = item.properties[i];
            if (p && typeof(p.type) != 'undefined' && p.type =='Property') {
                var name = extractIdentifierName(p.key);
                if (name == propertyName) return p;
            }
        }
    }
    return false;
}
// -------------------------------------------
function jQuery_processMemberExpressionArguments(first, second, exId) {
    var props = {};
    // handle $.ajax({type: "POST",..})
    if (first && typeof(first.type) != 'undefined' && first.type =='ObjectExpression') {
        props = extractPropertiesFromObjectExpression(first);
    }
    else {
        // take care of the URL first
        // handle $.post( "/ast/testfile.php", { name: "John", time: "2pm" } );
        if (first && typeof(first.type) != 'undefined' && first.type == 'Literal') {
            if (first && typeof(first.value) != 'undefined')
                props["url"] = first.value;
        }
        // the URL can be also a binary expression
        if (first && typeof(first.type) != 'undefined' && first.type == 'BinaryExpression') {
            props["url"] = evaluateBinaryExpression(first);
        }
        var theURL = props["url"];
        // now the data payload (if available)
        if (second && typeof(second.type) != 'undefined') {
            if (second.type == 'ObjectExpression')
            {
                var tempProps = extractPropertiesFromObjectExpression(second);
                // if the second object contains a property named "data" extract all properties
                if (typeof(tempProps.data) != 'undefined') props = extractPropertiesFromObjectExpression(second);
                // otherwise, extract just data
                else props["data"] = extractPropertiesFromObjectExpression(second);
            }
        }
        if (typeof(props.url) == 'undefined') props["url"] = theURL;
    }
    return props;
}
// -------------------------------------------
function processCallExpression(item) {
    if (typeof(item.callee) !== 'undefined' && typeof(item.arguments) !== 'undefined') {
        var callee = item.callee;
        var arguments = item.arguments;
        if (typeof(callee.type) !== 'undefined' && (callee.type =='MemberExpression' || callee.type =='Identifier')) {
            var exId = "";
            if (callee.type =='MemberExpression') exId = getExpressionId(callee);
            if (callee.type =='Identifier') exId = callee.name;
            if (!exId) return;
            debug("found expression " + exId);
            // $.ajax({type: "POST",..})
            if (
                // jQuery
            exId == "$.ajax" || exId == "$.post" || exId == "$.get"
            || exId == "jQuery.ajax" || exId == "jQuery.post" || exId == "jQuery.get"
            || exId == "$.load" || exId == "jQuery.load"
            || exId == "$.getScript" || exId == "$.getJSON"
            || exId == "jQuery.getScript" || exId == "jQuery.getJSON"
                // AngularJs
            || exId == "$http" || exId == "$http.get" || exId == "$http.head" || exId == "$http.post" || exId == "$http.put" || exId == "$http.delete" || exId == "$http.patch")
            {
                // prepare arguments
                // need to have at least one argument
                if (arguments.length <= 0) return;
                // get first argument
                var firstArgument = arguments[0];
                // second argument // $.post( "/ast/testfile.php", { name: "John", time: "2pm" } );
                var secondArgument = false;
                if (arguments.length > 1) secondArgument = arguments[1];
                var props = jQuery_processMemberExpressionArguments(firstArgument, secondArgument, exId);
                if (typeof(props["url"]) !== 'undefined' && props["url"] !== "1") {
                    var headers = {};
                    if (typeof(props["headers"]) !== 'undefined' && props["headers"])
                        headers = props["headers"];
                    var method = "GET";
                    if (exId == "$.post" || exId == "jQuery.post") method = "POST";
                    if (typeof(props["type"]) !== 'undefined' && props["type"])
                        method = props["type"];
                    else if (typeof(props["method"]) !== 'undefined' && props["method"])
                        method = props["method"];
                    if (method) method = method.toUpperCase();
                    var contentType = "application/x-www-form-urlencoded; charset=UTF-8";
                    if (typeof(props["contentType"]) !== 'undefined' && props["contentType"])
                        contentType = props["contentType"];
                    var data = "";
                    if (typeof(props["data"]) !== 'undefined' && props["data"])
                        data = props["data"];
                    var dataStr = "";
                    // json or simple POST
                    if (contentType.indexOf("json") != -1 && method != "GET") dataStr = convertDataObjectToStringJSON(data)
                    else dataStr = convertDataObjectToString(data);
                    var req = {
                        "method": method,
                        "url": props["url"],
                        "data": dataStr,
                        "contentType": contentType,
                        "headers": headers
                    };
                    processAjaxRequest(req);
                }
            }
        }
    }
}
// -------------------------------------------
function processAst(ast) {
    debug("processing ast ...");
    var elementsCount = ast.body.length;
    debug(elementsCount + " elements in the body");
    for (var i=0; i<elementsCount; i++) {
        recursiveFindCallExpressions(ast.body[i], "")
    }
}
// -------------------------------------------
function processJavaScriptCode(data) {
    try {
        var ast = acorn.parse(data);
        if (ast) processAst(ast);
    }
    catch(x){}
}
//module.exports.processJavaScriptCode = processJavaScriptCode;