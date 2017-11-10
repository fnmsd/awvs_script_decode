#include string_helpers.inc;
function SearchInputInScript(script, inputFoundAt, found){
	found.insideScriptSingleQuote = false;
	found.insideScriptDoubleQuote = false;
    found.insideCommentInline = false;
	found.insideCommentMultiline = false;
	for(var i=0; i<inputFoundAt; i++){
        if (script.substr(i, 1)=="\\")
        {
        	i++;
        	continue;
        }
        	
		if((!found.insideCommentInline && !found.insideCommentMultiline) 
            && (!found.insideScriptSingleQuote && !found.insideScriptDoubleQuote)
            && script.substr(i, 2)=="//")            
			found.insideCommentInline = true;
		else
            
		if(found.insideCommentInline && (script.substr(i, 1)=="\r" || script.substr(i, 1)=="\n"))                        
			found.insideCommentInline = false;        
		else
            
		if((!found.insideCommentInline && !found.insideCommentMultiline) 
            && (!found.insideScriptSingleQuote && !found.insideScriptDoubleQuote) 
            && script.substr(i, 2)=="/*")                        
			found.insideCommentMultiline = true;
		else
            
		if(found.insideCommentMultiline && script.substr(i, 2)=="*/")            
			found.insideCommentMultiline = false;
		else
            
		if((!found.insideCommentInline && !found.insideCommentMultiline) && !found.insideScriptDoubleQuote && script.substr(i, 1)=="'")            
			found.insideScriptSingleQuote = !found.insideScriptSingleQuote;
        
		else
            
		if((!found.insideCommentInline && !found.insideCommentMultiline) && !found.insideScriptSingleQuote && script.substr(i, 1)=='"')
			found.insideScriptDoubleQuote = !found.insideScriptDoubleQuote;
	}
}
function CompareObjects(obj1, obj2) {
    for (var p1 in obj1)
        if (obj1[p1] != obj2[p1]) return false;
    for (var p2 in obj2) 
        if (obj2[p2] != obj1[p2]) return false;
    return true;
}	
function SearchInputInResponse(input, body) {
	var insideTitleTag = false;
	var insideScriptTag = false;
	var insideTextareaTag = false;
	
	var angularCounter = -1;
	var angularTag = '';
		
    var founds = new Array();
    var foundsCounter = {};
    
    var pushit = function (obj) {
    	for (prop in obj)
    		if (obj.hasOwnProperty(prop)) {
    			if (prop in foundsCounter) {
    				foundsCounter[prop]++;
    				// don't want to add more than 5 of the same kind
    				if (foundsCounter[prop] > 5) return;    					
    			}
    			else {
    				foundsCounter[prop] = 1;
    			}
    		}
    		
		founds.push(obj);    		
    }
	
	if ((body.indexOfCi(input)==-1)) return founds;	
	
	var tokens = htmlTokens(body);
	var token = null;
	while (token = tokens.nextToken()) {
		// input is present in token?
		var inputFoundAt = token.raw.indexOfCi(input);
		if (inputFoundAt != -1) {
			if(token.isText){
				if (insideTitleTag) pushit({insideTitle:true});
				else if (insideScriptTag){
					var script = token.raw;
                    pushit({insideScript:true});
					SearchInputInScript(script, inputFoundAt, founds[founds.length-1]);
				}
				else if (insideTextareaTag) pushit({insideTextarea:true});
				else pushit({insideText:true, inputFoundAt: inputFoundAt, insideAngularJs:(angularCounter>=0)});
			}
			else if (token.isComment) pushit({insideComment:true});
			else if (token.isTag) {  
				// tagname
				if (token.tagName.toLowerCase() == input.toLowerCase()) {
					pushit({insideTag:true});
					continue;
				}		
						
				// check parameters
				for(var i=0; i<token.paramCount; i++) {
					var parName = token.getParamName(i);
					var parValue = token.getParamValue(i);
					
					// name first
					inputFoundAt = parName.indexOfCi(input);
					
					if (inputFoundAt != -1) {
						pushit({insideTag:true});
						continue;
					}
					
					// parameter value
					inputFoundAt = parValue.indexOfCi(input);
					if (inputFoundAt != -1) {
						
						var quoteChar = token.getParamQuote(i);
						if (quoteChar == '') pushit({insideTag:true});
						else if (quoteChar == "'") pushit({insideTagSingleQuotes:true, insideAngularJs:(angularCounter>=0)});
						else if (quoteChar == '"') pushit({insideTagDoubleQuotes:true, insideAngularJs:(angularCounter>=0)});
						if (parValue.indexOfCi('javascript:') == 0) {
								var script = parValue.substr(11);
                                pushit({insideJavascript:true,insideScriptPosition:(inputFoundAt-11),parName:parName});
								SearchInputInScript(script, inputFoundAt-11, founds[founds.length-1]);
						}
                        else
						if (parValue.indexOfCi('vbscript:') == 0) {
								var script = parValue.substr(9);
                                pushit({insideJavascript:true,insideScriptPosition:(inputFoundAt-9), parName:parName});
								SearchInputInScript(script, inputFoundAt-9, founds[founds.length-1]);
						}
                        else
                        if (
                            (token.tagName == 'FORM' && parName == "ACTION")  ||
                            (token.tagName == 'A' && parName == "HREF") ||
                            (token.tagName == 'FRAME' && parName == "SRC") ||
                            (token.tagName == 'IFRAME' && parName == "SRC")
                            )
                        {
                            var script = parValue;
                            if (inputFoundAt==0) {
                                pushit({insideFormActionAHref:true}); 
                            }
                        }
                        else
                        if  (token.tagName == 'META' && parName == "CONTENT")
                        {
                                var foundRefresh = false;
                                for(var k=0; k<token.paramCount; k++) {
    					            var tempParName = token.getParamName(k);
    					            var tempParValue = token.getParamValue(k).toUpperCase();
                                    
                                    if (tempParName == "HTTP-EQUIV" && tempParValue == "REFRESH") 
                                    {   
                                        foundRefresh = true;
                                        break;
                                    } 
                                }
                                
                                var matchRegex = "\\d+\s*\\;\s*url\\s*=\\s*['\"]?" + input + ".*";
                                if (foundRefresh && parValue.match(matchRegex)) {
                                    var script = parValue;
                                    pushit({insideMetaRefresh:true}); 
                                }
                        }
                        
                        else
                            
                        if (
                            parName == "ONAFTERPRINT" || 
                            parName == "ONBEFOREPRINT" || 
                            parName == "ONBEFOREONLOAD" || 
                            parName == "ONBLUR" || 
                            parName == "ONERROR" || 
                            parName == "ONFOCUS" || 
                            parName == "ONHASCHANGE" || 
                            parName == "ONLOAD" || 
                            parName == "ONMESSAGE" || 
                            parName == "ONOFFLINE" || 
                            parName == "ONONLINE" || 
                            parName == "ONPAGEHIDE" || 
                            parName == "ONPAGESHOW" || 
                            parName == "ONPOPSTATE" || 
                            parName == "ONREDO" || 
                            parName == "ONRESIZE" || 
                            parName == "ONSTORAGE" || 
                            parName == "ONUNDO" || 
                            parName == "ONUNLOAD" || 
                            parName == "ONBLUR" || 
                            parName == "ONCHANGE" || 
                            parName == "ONCONTEXTMENU" || 
                            parName == "ONFOCUS" || 
                            parName == "ONFORMCHANGE" || 
                            parName == "ONFORMINPUT" || 
                            parName == "ONINPUT" || 
                            parName == "ONINVALID" || 
                            parName == "ONRESET" || 
                            parName == "ONSELECT" || 
                            parName == "ONSUBMIT" || 
                            parName == "ONKEYDOWN" || 
                            parName == "ONKEYPRESS" || 
                            parName == "ONKEYUP" || 
                            parName == "ONCLICK" || 
                            parName == "ONDBLCLICK" || 
                            parName == "ONDRAG" || 
                            parName == "ONDRAGEND" || 
                            parName == "ONDRAGENTER" || 
                            parName == "ONDRAGLEAVE" || 
                            parName == "ONDRAGOVER" || 
                            parName == "ONDRAGSTART" || 
                            parName == "ONDROP" || 
                            parName == "ONMOUSEDOWN" || 
                            parName == "ONMOUSEMOVE" || 
                            parName == "ONMOUSEOUT" || 
                            parName == "ONMOUSEOVER" || 
                            parName == "ONMOUSEUP" || 
                            parName == "ONMOUSEWHEEL" || 
                            parName == "ONSCROLL" || 
                            parName == "ONABORT" || 
                            parName == "ONCANPLAY" || 
                            parName == "ONCANPLAYTHROUGH" || 
                            parName == "ONDURATIONCHANGE" || 
                            parName == "ONEMPTIED" || 
                            parName == "ONENDED" || 
                            parName == "ONERROR" || 
                            parName == "ONLOADEDDATA" || 
                            parName == "ONLOADEDMETADATA" || 
                            parName == "ONLOADSTART" || 
                            parName == "ONPAUSE" || 
                            parName == "ONPLAY" || 
                            parName == "ONPLAYING" || 
                            parName == "ONPROGRESS" || 
                            parName == "ONRATECHANGE" || 
                            parName == "ONREADYSTATECHANGE" || 
                            parName == "ONSEEKED" || 
                            parName == "ONSEEKING" || 
                            parName == "ONSTALLED" || 
                            parName == "ONSUSPEND" || 
                            parName == "ONTIMEUPDATE" || 
                            parName == "ONVOLUMECHANGE" || 
                            parName == "ONWAITING" || 
							parName == "ONTOUCHSTART" || 
							parName == "ONTOUCHMOVE" || 
							parName == "ONTOUCHEND" || 
							parName == "ONTOUCHENTER" || 
							parName == "ONTOUCHLEAVE" || 
							parName == "ONTOUCHCANCEL" ||           
							parName == "ONGESTURESTART" || 
							parName == "ONGESTURECHANGE" || 
							parName == "ONGESTUREEND" || 
							parName == "ONPOINTERDOWN" || 
							parName == "ONPOINTERUP" || 
							parName == "ONPOINTERCANCEL" || 
							parName == "ONPOINTERMOVE" || 
							parName == "ONPOINTEROVER" || 
							parName == "ONPOINTEROUT" || 
							parName == "ONPOINTERENTER" || 
							parName == "ONPOINTERLEAVE" || 
							parName == "ONGOTPOINTERCAPTURE" || 
							parName == "ONLOSTPOINTERCAPTURE" || 
							parName == "ONCUT" || 
							parName == "ONCOPY" || 
							parName == "ONPASTE" || 
							parName == "ONBEFORECUT" || 
							parName == "ONBEFORECOPY" || 
							parName == "ONBEFOREPASTE" || 
							parName == "ONAFTERUPDATE" || 
							parName == "ONBEFOREUPDATE" || 
							parName == "ONCELLCHANGE" || 
							parName == "ONDATAAVAILABLE" || 
							parName == "ONDATASETCHANGED" || 
							parName == "ONDATASETCOMPLETE" || 
							parName == "ONERRORUPDATE" || 
							parName == "ONROWENTER" || 
							parName == "ONROWEXIT" || 
							parName == "ONROWSDELETE" || 
							parName == "ONROWINSERTED" || 
							parName == "ONCONTEXTMENU" || 
							parName == "ONDRAG" || 
							parName == "ONDRAGSTART" || 
							parName == "ONDRAGENTER" || 
							parName == "ONDRAGOVER" || 
							parName == "ONDRAGLEAVE" || 
							parName == "ONDRAGEND" || 
							parName == "ONDROP" || 
							parName == "ONSELECTSTART" || 
							parName == "ONHELP" || 
							parName == "ONBEFOREUNLOAD" || 
							parName == "ONSTOP" || 
							parName == "ONBEFOREEDITFOCUS" || 
							parName == "ONSTART" || 
							parName == "ONFINISH" || 
							parName == "ONBOUNCE" || 
							parName == "ONBEFOREPRINT" || 
							parName == "ONAFTERPRINT" || 
							parName == "ONPROPERTYCHANGE" || 
							parName == "ONFILTERCHANGE" || 
							parName == "ONREADYSTATECHANGE" || 
							parName == "ONLOSECAPTURE" || 
							parName == "ONDRAGDROP" || 
							parName == "ONDRAGENTER" || 
							parName == "ONDRAGEXIT" || 
							parName == "ONDRAGGESTURE" || 
							parName == "ONDRAGOVER" || 
							parName == "ONCLOSE" || 
							parName == "ONCOMMAND" || 
							parName == "ONINPUT" || 
							parName == "ONCONTEXTMENU" || 
							parName == "ONOVERFLOW" || 
							parName == "ONOVERFLOWCHANGED" || 
							parName == "ONUNDERFLOW" || 
							parName == "ONPOPUPHIDDEN" || 
							parName == "ONPOPUPHIDING" || 
							parName == "ONPOPUPSHOWING" || 
							parName == "ONPOPUPSHOWN" || 
							parName == "ONBROADCAST" || 
							parName == "ONCOMMANDUPDATE" || 
                            parName == "STYLE"
                            ) 
                        {
                            var script = parValue;
                            pushit({insideJavascript:true,insideScriptPosition:(inputFoundAt),parName:parName});
							SearchInputInScript(script, inputFoundAt, founds[founds.length-1]);
                        }                        
					}
				}
			}
		}
		// token is a tag?
		if (token.isTag) 
		{ 
			//trace(angularCounter + " " + token.tagName);
			
			if (token.tagName == 'TITLE') insideTitleTag = true;
			else if (token.tagName == '/TITLE') insideTitleTag = false;
			else if (token.tagName == 'SCRIPT') insideScriptTag = true;
			else if (token.tagName == '/SCRIPT') insideScriptTag = false;	
			else if (token.tagName == 'TEXTAREA') insideTextareaTag = true;
			else if (token.tagName == '/TEXTAREA') insideTextareaTag = false;	
			
			// take care of AngularJs 					
			
			// lookup for tag matching the angular Js starting tag
			if (angularTag && token.tagName == angularTag && angularCounter >= 0) {
				angularCounter += 1;
				
				//trace("counter: " + angularCounter);
				
			} else 
			
			// lookup for tag matching the angular Js ending tag	
			if (angularTag && token.tagName == '/' + angularTag && angularCounter >= 0) {
				angularCounter -= 1;
				
				//trace("counter: " + angularCounter);
			
				// reset angularTag
				if (angularCounter < 0) angularTag = "";
			}
			
			// lookup for a tag with AngularJs attribute
			for(var i=0; i<token.paramCount; i++) {
				var parName = token.getParamName(i);
			
				if ((parName == 'NG-APP' || parName == 'DATA-NG-APP')) {
					angularCounter += 1;
					angularTag = token.tagName;
					
					//trace("counter: " + angularCounter);
				}								
			}
 
		}		
	}
	
	return founds;    
}
