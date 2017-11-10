// **************************************************************************************							 
function alertUploadify(uri, vxml, job, matchedText)
{	
	var ri = new TReportItem();
	ri.LoadFromFile(vxml);
	ri.affects = uri;
	ri.alertPath = "Scripts/" + vxml; 	
	ri.setHttpInfo(job);
	addHTTPJobToCrawler(job, 1, 1);
	
	AddReportItem(ri);	
}							 			
/***********************************************************************************/
function testUploadifyOnURI(uri)
{
    //trace('test uploadify on ' + uri);
    var lastJob = null;
	lastJob = new THTTPJob();
	lastJob.verb = "POST";
	lastJob.url  = scanURL;	
	lastJob.uri  = uri;		
	lastJob.request.addHeader("Content-Type", "multipart/form-data; boundary=-----Boundary_DRSMECKONC", true);
	
	lastJob.request.body = 
        '-------Boundary_DRSMECKONC' + CRLF() +
        'Content-Disposition: form-data; name="folder"' + CRLF() +
        '' + CRLF() +
        '.' + CRLF() +
        '-------Boundary_DRSMECKONC' + CRLF() +
        'Content-Disposition: form-data; name="Filedata"; filename="acunetix-uploadify-test.php"' + CRLF() +
        'Content-Type: text/plain' + CRLF() +
        '' + CRLF() +
        '082119f75623eb7abd7bf357698ff66c' + CRLF() +
        '-------Boundary_DRSMECKONC--' + CRLF();
	
	lastJob.execute();
	
	if (!lastJob.wasError && !lastJob.notFound) 
	{
		if (lastJob.responseStatus == 200 && lastJob.response.body.indexOf("/acunetix-uploadify-test.php") != -1)
		{
			// upload was successful
			alertUploadify(uri, 'Uploadify_Arbitrary_File_Upload.xml', lastJob);
			return true;				
		}
	}		
	
	return false;
}
