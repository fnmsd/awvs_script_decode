// **************************************************************************************
function checkForCustom404(file, padding) {
	var dirName = file.path + file.name;
	if (dirName.charAt(dirName.length-1) != '/') dirName = dirName + '/'; 		
	var uri = dirName + randStr(10) + padding;
	
	var http = new THTTPJob();
	
	http.url = scanURL;
	http.verb = 'GET';
	http.URI = uri;
	http.request.addHeader('Accept', 'acunetix/wvs', true);
	http.execute();	
	
	return http.wasError || !http.notFound;	
}
// **************************************************************************************
function thisFolderIsARootFolder(file){
	var dirPath = file.fullPath + "/";	
	dirPath = dirPath.replace(scanURL.path, "/");	
	parts = dirPath.split("/");
	
	if (parts.length <= 2) return true;
	return false;
}
// **************************************************************************************
function canIScanThisFolder(file){
	// don't scan if acusensor is enabled
	if (file.hasAcuSensor) return false;	
    
	// don't scan if was already marked as excluded from perDir scanning
	if (file.isMarkedAs(MARKED_AS_InvalidForPerDirTesting)) {
		return false;
	}
	
	// don't test if was already marked as excluded from perDir scanning
	if (file.isMarkedAs(MARKED_AS_ValidForPerDirTesting)) {
		return true;
	}
	
	var ExcludedFromPerDir = checkForCustom404(file, '') 
							|| checkForCustom404(file, '.php') 
							|| checkForCustom404(file, '.html') 
							|| checkForCustom404(file, '.jsp');
	
	if (ExcludedFromPerDir) {
		file.markAs(MARKED_AS_InvalidForPerDirTesting);
	} else {
		file.markAs(MARKED_AS_ValidForPerDirTesting);
	}	
	return !ExcludedFromPerDir;
}
// **************************************************************************************
function acuSensorWasEnabled(file){
	var iter = file;
	while (iter)
	{
		if (iter.hasAcuSensor) {
			return true;
		}
		
		iter = iter.getParent();
	}	
	return false;
}