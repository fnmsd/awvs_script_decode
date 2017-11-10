{
	function classMatches()
	{
		this.plainArray = [];
		this.regexArray = [];							
	}
	
	classMatches.prototype.searchOnText = function(text) 
	{
		// search plain texts first
        if (this.plainArray.length > 0)
		for (var i=0;i<this.plainArray.length;i++) 
		{
			if (text.indexOf(this.plainArray[i]) != -1) 
				return this.plainArray[i];
		}
			
		// search regexes
        if (this.regexArray.length > 0)
		for (var i=0;i<this.regexArray.length;i++) 
		{
			var m = this.regexArray[i].exec(text);
			if (m) return m[0];
		}						
		return false;	
	}
}
