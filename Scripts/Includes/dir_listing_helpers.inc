{
	function classDirListingMatches(){
		this.plainArray = 	[
                                '<title>Directory Listing For',
								'Directory Listing for',
								'Last modified<\/a>',	
								'<TITLE>Folder Listing',
								'<TITLE>Directory: /',
								'<table summary="Directory Listing"'				
							];
		
		this.regexArray = 	[
								/<A\sHREF="[^"]*">\[To\sParent\sDirectory]<\/A>/i,
								/<body><h1>Directory\sListing\sFor\s.*<\/h1>/i,
								/<HTML><HEAD><TITLE>Directory:.*?<\/TITLE><\/HEAD><BODY>/i,
								/<a href="\?C=[NMSD];O=[AD]">Name<\/a>/i,
								/<title>Index\sof\s.*?<\/title>/i
								
							];											
	}
	
	classDirListingMatches.prototype.searchOnText = function(text) {
		// search plain texts first
		for (var i=0;i<this.plainArray.length;i++) {
			var result= text.search(new RegExp(this.plainArray[i], "i"));			
			if (result != -1) {
					return this.plainArray[i];	
			}
		}
			
		// search regexes
		for (var i=0;i<this.regexArray.length;i++) {
			var m = this.regexArray[i].exec(text);
			if (m) return m[0];
		}			
			
		return false;	
	}
}
