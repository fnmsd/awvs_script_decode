function getEmailStorage(){
    return GetGlobalValue("emailStorage");
}
function validEmail(email) {
    if (email && (email.toLowerCase().endsWith(".png") || email.toLowerCase().endsWith(".jpg"))) {
        return false;
    }
    return true;
}
function emailAlreadyInList(storage, email) {
    if (storage) {
        //trace('storage is: ' + storage);
        var emails = storage.split("\r\n");
        for (var i=0; i<emails.length; i++){
            if (emails[i] && emails[i] == email) {
                return true;
            }
        }
    }
    return false;
}
function addEmailAddressesForLaterUsage(list){
    var baseDomain = getBaseDomain(scanURL);
    var storage = getEmailStorage();
    var emails = list.split("\r\n");
    
    for (var i=0; i<emails.length; i++){
        if (emails[i] && !emailAlreadyInList(storage, emails[i]) && validEmail(emails[i])) {
            
            parts = emails[i].split("@");
            if (parts && parts.length == 2 && baseDomain.indexOf(parts[1]) != -1) {            
                            
                if (storage) storage = storage + emails[i] + "\r\n";
                else storage = emails[i] + "\r\n";
                
                setGlobalValue("emailStorage", storage, true);
                //trace('add email ' + emails[i]);
            }
        }
    }
}