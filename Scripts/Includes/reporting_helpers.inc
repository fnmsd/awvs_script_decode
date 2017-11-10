// create KBase item
// KBName = name of KBase item (e.g. "Echo service running")
// KBText = KBase item text (e.g. "An echo service is running on this host.")
function KBase(KBname, KBtext){
	var kbi = new TKBaseItem();  
	kbi.Name = KBname;
	kbi.Text = KBtext;
	AddKBItem(kbi);
}
// create report item
// RIfname = vulnxml filename (e.g. "Chargen.xml")
// RIdetails = report details (e.g. "Chargen service is running on UDP port 19")
function ReportItem(RIfname, RIdetails){
	
	var ri = new TReportItem();
 	ri.LoadFromFile(RIfname);
 	ri.Affects = "Server";
  	ri.AlertPath = "Scripts/" + RIfname;
  	ri.Details = RIdetails;
  
	AddReportItem(ri);	
}
// compute progress
function ComputeProgress(current, max)
{
	var res = Math.floor(100*current/max);
	//if (res < 0) {res = 0;}
	
	return res;
}