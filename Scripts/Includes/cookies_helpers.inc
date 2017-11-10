// requires string_helpers.inc
function extractCookiesFromResponse(response) {
    var cookies = new Array();
    var cookieValues = new TStringList();
    response.headerValues('set-cookie', cookieValues);  
    
    for (var i=0; i<cookieValues.count; i++) {
        cv = cookieValues.item(i);
        var tempCookies = cv.split(';');
        for (var j=0; j<tempCookies.length; j++) {
            var parts = tempCookies[j].split('=');
            if (parts.length == 2) {
                var name  = parts[0].trim();
                var value = (parts[1] || "").trim();
                cookies[name] = value;
            }
        }    
    }
    return cookies;
}