function isArray() 
{
	try
	{
		if ((typeof arguments[0] == 'object') && (arguments[0].constructor != null))
		{
			var criterion = arguments[0].constructor.toString().match(/\s*function\s*Array\s*\(/i);
			return (criterion != null);  
		}
	}
	catch(error)
	{
	}
	return false;
}
// traceObject(object, objectname)
function traceObject(obj, strName, strIndent, intDepth, intMaxDepth, boolSkipFunctions)
{
	if(intDepth == null) intDepth = 0;
	if(intMaxDepth == null) intMaxDepth = 10;
	if(strIndent == null) strIndent = "";
	if(strName == null) strName = "object";
	if(boolSkipFunctions ==null) boolSkipFunctions = true;
	strIndent = strIndent + '  ';
	if(intDepth > intMaxDepth)
	{
		trace(strIndent + strName + ' : ' + "<Maximum Depth Reached>");
		return;
	}
	if (typeof obj == "function")
	{
		if(!boolSkipFunctions) trace(strIndent + strName + ' : ' + "<Function>");
		return;
	}
	if (typeof obj == "object")
	{
		if(isArray(obj))
			trace(strIndent + strName + ' : ' + "<Array>");
		else
			trace(strIndent + strName + ' : ' + "<Object>");
		var child = 0;
		for (var item in obj)
		{
			try
			{
			  child = obj[item];
			} catch (e)
			{
				trace(strIndent + '  ' + "<Unable to Evaluate>");
				return;
			}
			traceObject(child, item, strIndent + '  ', intDepth + 1, intMaxDepth, boolSkipFunctions);
		}
		return;
	}
	trace(strIndent + strName + ' : ' + obj);
}