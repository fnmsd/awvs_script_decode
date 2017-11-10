// init stuff
var lastJob = null;
var ttTestFiles = Array(
    "timthumb.php",
    "img.php",
    "thumb.php",
    "inc/thumb.php",
    "themify/img.php",
    "library/timthumb.php",
    "tools/timthumb.php",
    "scripts/timthumb.php",
    "lib/timthumb.php",
    "includes/timthumb.php",
    "modules/timthumb.php",
    "images/timthumb.php"
);
var ttThemes = Array(
    "13floor",
    "8q",
    "aerial",
    "parallax",
    "aesthete",
    "albizia",
    "amphion-lite",
    "Apz",
    "aqua-blue",
    "aranovo",
    "arras",
    "arras-theme",
    "arthemix-bronze",
    "arthemix-green",
    "artisan",
    "a-simple-business-theme",
    "AskIt",
    "a-supercms",
    "aureola",
    "aurorae",
    "automotive-blog-theme",
    "backstage",
    "Basic",
    "black_eve",
    "blex",
    "bloggnorge-a1",
    "blogified",
    "blue-corporate-hyve-theme",
    "bluemag",
    "blue-news",
    "Bold",
    "bombax",
    "breakingnewz",
    "brightsky",
    "brochure-melbourne",
    "bueno",
    "business-turnkey",
    "busybee",
    "calotropis",
    "canvas",
    "Chameleon",
    "cinch",
    "cityguide",
    "coffeebreak",
    "ColdStone",
    "comet",
    "comfy-3.0.9",
    "conceditor-wp-strict",
    "constructor",
    "coverht-wp",
    "cover-wp",
    "crisp",
    "dailyedition",
    "dark-dream-media",
    "deep-blue",
    "DeepFocus",
    "delegate",
    "delicate",
    "diarise",
    "digitalfarm",
    "dimenzion",
    "eGamer",
    "ElegantEstate",
    "eNews",
    "epione",
    "eVid",
    "evr-green",
    "famous",
    "featuring",
    "flashnews",
    "fliphoto",
    "flix",
    "fresh-blu",
    "freshnews",
    "gazette",
    "genoa",
    "Glow",
    "go-green",
    "granite-lite",
    "greydove",
    "greyzed",
    "headlines",
    "heli-1-wordpress-theme",
    "here-comes-the-bride",
    "ideatheme",
    "impressio",
    "inspire",
    "irresistible",
    "iwana-v10",
    "jellyfish",
    "LightBright",
    "likehacker",
    "litepress",
    "magazinum",
    "Magnificent",
    "magup",
    "make-money-online-theme-1",
    "make-money-online-theme-2",
    "make-money-online-theme-3",
    "make-money-online-theme-4",
    "make-money-online-theme",
    "max-3.0.0",
    "metamorphosis",
    "mimbopro",
    "Minimal",
    "modularity",
    "moi-magazine",
    "my-heli",
    "mymag",
    "MyProduct",
    "mystique",
    "mystream",
    "nash",
    "neofresh",
    "new-green-natural-living-ngnl",
    "newsworld-1.0.0",
    "newsworld",
    "nomadic",
    "Nova",
    "object",
    "OnTheGo",
    "openair",
    "OptimizePress",
    "optimize",
    "overeasy",
    "pearlie",
    "PersonalPress",
    "pico",
    "Polished",
    "postage-sydney",
    "postcard",
    "premiumnews",
    "probluezine",
    "profitstheme_11",
    "profitstheme",
    "PureType",
    "Quadro",
    "redcarpet",
    "regal",
    "retreat",
    "royalle",
    "sealight",
    "shaan",
    "shadow",
    "simple-but-great",
    "simplenews_premium",
    "SimplePress",
    "simple-red-theme",
    "simplewhite",
    "skeptical",
    "slanted",
    "slidette",
    "snapshot",
    "sophisticatedfolio",
    "spectrum",
    "sportpress",
    "spotlight",
    "squeezepage",
    "suffusion",
    "swift",
    "TheCorporation",
    "the_dark_os",
    "thejournal",
    "themorningafter",
    "TheProfessional",
    "TheSource",
    "thestation",
    "TheStyle",
    "tm-theme",
    "totallyred",
    "travelogue-theme",
    "true-blue-theme",
    "ttnews-theme",
    "twittplus",
    "typebased",
    "typographywp",
    "ugly",
    "unity",
    "versitility",
    "vibefolio-teaser-10",
    "Widescreen",
    "wootube",
    "wpbus-d4",
    "wp-creativix",
    "wp-newsmagazine",
    "wp-perfect",
    "wp-premium-orange",
    "zcool-like",
    "TheStyle" 
)
var ttPlugins = Array(
    "a-gallery",
    "dukapress",
    "front-slider",
    "woo-tumblog",
    "geotag",
    "highlighter",
    "igit-posts-slider-widget",
    "igit-related-posts-with-thumb-images-after-posts",
    "islidex",
    "jquery-slider-for-featured-content",
    "kc-related-posts-by-category",
    "lisl-last-image-slider",
    "meenews",
    "meenews-newsletter",
    "mobile-smart",
    "seo-image-galleries",
    "shortcodes-ultimate",
    "smart-related-posts-thumbnails",
    "webphysiology-portfolio",
    "wordpress-gallery-plugin",
    "wp-mobile-detector",
    "wp-slick-slider",
    "social-profiles-widget",
    "portfolio-slideshow-pro",
    "a-wp-mobile-detector",
    "verve-meta-boxes",
    "db-toolkit",
    "logo-management",
    "wp-marketplace",
    "aio-shortcodes",
    "category-grid-view-gallery",
    "WPFanPro",
    "cms-pack",
    "Premium_Gallery_Manager",
    "dp-thumbnail",
    "placid-slider",
    "nivo-slider",
    "photoria",
    "LaunchPressTheme",
    "journalcrunch",
    "download-manager",
    "wordpress-thumbnail-slider",
    "sugar-slider",
    "optimizepress",
    "auto-attachments",
    "vk-gallery",
    "rekt-slideshow",
    "cac-featured-content",
    "rent-a-car",
    "kino-gallery",
    "category-list-portfolio-page",
    "really-easy-slider",
    "add-new-default-avatar-emrikols-fork",
    "communitypress",
    "event-espresso-free",
    "extend-wordpress",
    "featured-post-with-thumbnail",
    "feature-slideshow",
    "fotoslide",
    "hungred-image-fit",
    "igit-related-posts-widget",
    "image-rotator-widget",
    "image-symlinks",
    "mangapress",
    "mediarss-external-gallery",
    "mobileposty-mobile-site-generator",
    "pictmobi-widget",
    "sharepulse",
    "sh-slideshow",
    "simple-coverflow",
    "simple-post-thumbnails",
    "simple-slide-show",
    "sliceshow-slideshow",
    "tag-gallery",
    "thethe-image-slider",
    "thumbnails-anywhere",
    "timthumb-meets-tinymce",
    "timthumb-vulnerability-scanner",
    "tim-widget",
    "todo-espaco-online-links-felipe",
    "uBillboard",
    "vslider",
    "wordpress-news-ticker-plugin",
    "wordpress-popular-posts",
    "wp-dailybooth",
    "wp-featured-post-with-thumbnail",
    "wp-pagenavi",
    "wps3slider",
    "wptap-news-press-themeplugin-for-iphone",
    "wp-thumbie",
    "yd-export2email",
    "yd-recent-posts-widget",
    "zingiri-web-shop"
);
// **************************************************************************************							 
function request(_dir, uri, testForVuln)
{	
	lastJob = new THTTPJob();
	lastJob.verb = "GET";
	lastJob.url  = _dir.url;
    
    if (testForVuln)lastJob.uri  = uri + "?src=http://blogger.com.vulnweb.com/" + randStr(8) + ".php";
    else lastJob.uri  = uri;
    
	lastJob.execute();
	return (!lastJob.wasError); 
}
// **************************************************************************************							 
function alert(uri, vxml)
{	
	var ri = new TReportItem();
	ri.LoadFromFile(vxml);
	ri.affects = uri;
	ri.alertPath = "Scripts/Wordpress/TimThumb";	
	ri.setHttpInfo(lastJob);
	
	AddReportItem(ri);	
}							 	
// **************************************************************************************
function testTimThumbOnDirectory(_dir, dir){
    //trace(dir);
    
    var found = false;
    
    for (var i=0; i<ttTestFiles.length; i++) 
	{
        var fname = dir + ttTestFiles[i];
        // trace(fname);
        if (request(_dir, fname, true))
        {
            if (lastJob.response.body.indexOf("Couldn't resolve host 'blogger.com.vulnweb.com'") != -1)
            {
                    // trace(fname + " vuln");
                    alert(fname, "TimThumb_domain_exploit.xml");
                    found = true;
                    break;
            }
        }        
    }
    return found;
}		
// **************************************************************************************
function testTimThumb(dir){
    root_path = dir.fullPath;
    if (root_path.charAt(root_path.length-1) != '/') root_path = root_path + '/';
    
    //trace(root_path);
    //trace(dir.response.body);
    
    var foundOnTheme = false;        
    
    if (dir.response.body != "") {
        var m = /.\/wp-content\/themes\/([^/]+)\//.exec(dir.response.body);
	    if (m && m[1]) {
            theme_name = m[1];
            foundOnTheme = testTimThumbOnDirectory(dir, root_path + "wp-content/themes/" + theme_name + "/");
        }
    }
    
    var foundOnPlugins = false;
    
    if (!foundOnTheme) 
    {
        // test on known vulnerable plugins
        for (var i=0; i<ttPlugins.length; i++) 
        {
            plugin_dir = root_path + "wp-content/plugins/" + ttPlugins[i];
            if (request(dir, plugin_dir))
            {
                if (lastJob.responseStatus == 301 || lastJob.responseStatus == 302)
                {
                    var locationStr = lastJob.response.headerValue('location');
        			if (locationStr && locationStr.indexOf(plugin_dir + "/") != -1)  
                    {
                        // trace("found plugin " + plugin_dir);
                        foundOnPlugins = testTimThumbOnDirectory(dir, plugin_dir + "/");
                        if (foundOnPlugins) break;
                    }
                }
            }
        }        
    }
    
    var foundOnThemes2 = false;
    if (!foundOnPlugins) 
    {
        // test on known vulnerable themes
        for (var i=0; i<ttThemes.length; i++) 
        {
            theme_dir = root_path + "wp-content/themes/" + ttThemes[i];
            if (request(dir, theme_dir))
            {
                if (lastJob.responseStatus == 301 || lastJob.responseStatus == 302)
                {
                    var locationStr = lastJob.response.headerValue('location');
        			if (locationStr && locationStr.indexOf(theme_dir + "/") != -1)  
                    {
                        // trace("found theme " + theme_dir);
                        foundOnThemes2 = testTimThumbOnDirectory(dir, theme_dir + "/");
                        if (foundOnThemes2) break;
                    }
                }
            }
        }        
    }    
}