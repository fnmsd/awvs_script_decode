// **************************************************************************************
function leetSpeak(input) {
	var LettersEnglish = 
	    new Array('a', 'e', 'o', 'i');
	var LettersLeet = 
	    new Array('4', '3', '0', '1');
	for (i = 0; i < LettersEnglish.length; ++i)
		input = input.replace(
	        new RegExp(LettersEnglish[i], "gi"),
	        LettersLeet[i]
	        );
		
	return input;
}