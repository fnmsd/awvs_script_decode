// **************************************************************************************
function toTitleCase(str)
{
	var out = str.charAt(0).toUpperCase() + str.substr(1).toLowerCase()
    return out.replace("Wordpress", "WordPress");
}
