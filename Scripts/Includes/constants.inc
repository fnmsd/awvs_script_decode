// input flags
var INPUT_FLAG_EQ_MISSING               = 0x1; 	// for URL encoded inputs
var INPUT_FLAG_MISSING_IF_EMPTY         = 0x2; 	// for checkbox inputs from forms
var INPUT_FLAG_IS_FILE                  = 0x4; 	// for multipart form data
var INPUT_FLAG_DONT_QUOTE_JSON          = 0x8;   // for some special values the result will not be quoted
var INPUT_FLAG_IS_PASSWORD              = 0x10;  // input is password field from form
var INPUT_FLAG_IS_BUTTON                = 0x20;  // input is a button
var INPUT_FLAG_NUMERIC                  = 0x40;  // input has numeric values only
var INPUT_GROUP_FLAG_REFLECTION_TESTS   = 0x80;  // input should be tested for XSS and other type of reflection
var INPUT_FLAG_HAS_NAME                 = 0x100; // input has a name component
var INPUT_FLAG_CAN_BE_ARRAY             = 0x200; // input can be tested like name[]
var PP_UNKNOWN = 0;
var PP_FIRST = 1;
var PP_LAST = 2;
var PP_JOIN = 3;
// load flags (used when loading site files)
var loadParserData	= 1;
var loadHttp		= 2;
var loadAspectData	= 4;
var loadSchemes		= 8;
// aspect data (acusensor)
var ACUINJSTART	= "ACUSTART";
var ACUINJEND	= "ACUEND";
// injection helpers
var INJ_RND_CHARCOUNT = 5;
// reflection tests
var REFL_TEST_XSS 		= 0;
var REFL_TEST_SQL_INJ 	= 1;
var REFL_TEST_LFI 		= 2;
var REFL_TEST_DIRTRAV	= 3;
var	REFL_TEST_CODEEXEC	= 4;
var REFL_TEST_FILETAMP  = 5;
var REFL_TEST_PHPCODEEV = 6;
var MARKED_AS_CheckForURLRewrite        = 1;
var MARKED_AS_RealDir                   = 2;
var MARKED_AS_Invalid_Host              = 8;
var MARKED_AS_ValidForPerDirTesting     = 16;
var MARKED_AS_InvalidForPerDirTesting   = 32;
var MARKED_AS_PartOfLogin               = 64;
var MARKED_AS_Autoindex                 = 128;
var MARKED_AS_Autoindex_Checked         = 256;
var MARKED_AS_Discovered_From_Marvin    = 512;
