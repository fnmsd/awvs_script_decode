// various functions for auditing JSF viewstate
//--------------------------------------------------------------------------------------------------------
function JSFViewStateClientSide(viewstateStr)
{
    if (!viewstateStr) return false;
    if (viewstateStr.indexOf(":") !== -1) return false;
    if (viewstateStr.indexOf("-") !== -1) return false;
    if (viewstateStr.length < 50) return false;
    var match = viewstateStr.match(/^([A-Za-z\d\+/\=\s]+)$/);
    if (match && match[1]) {
        return true;
    }
    return false;
}