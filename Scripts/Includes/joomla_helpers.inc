// list of vulnerable plugins
var files = Array(
    // plugin_name, get, post 
    // plugin name: core is used for joomla core alerts so it is always installed 
    // plugin name: if plugin name starts with {admin} it will check if the plugin is installed in /administrator/components/
    ["core", "/index.php/extensions/components/content-component/article-category-list/?filter_order=acunetix_wvs,&filter_order_Dir=2&limit=3&limitstart=4", ""],
    ["core", "/htaccess.txt", ""],
    ["core", "/administrator/", ""],        
    ["core", "/admin/", ""],        
    ["core", "/libraries/phpxmlrpc/xmlrpcs.php|/libraries/phpxmlrpc/xmlrpcs.php", ""],        
    ["core", "/libraries/joomla/utilities/compat/php50x.php|/libraries/joomla/utilities/compat/php50x.php", ""],        
    ["core", "/includes/joomla.php|/includes/joomla.php?includepath=a", ""],        
    ["core", "/plugins/editors/xstandard/attachmentlibrary.php", ""],        
    ["core", "/libraries/pcl/pcltar.php?g_pcltar_lib_dir=a", ""],        
    ["core", "/libraries/phpmailer/phpmailer.php", ""],        
    ["core", "/plugins/editors/tinymce/jscripts/tiny_mce/plugins/tinybrowser/", ""],        
    ["core", "/components/com_user/controller.php", ""],        
    ["core", "/components/com_content/", ""],        
    ["core", "/index.php?option=com_content&task=blogcategory&id=60&Itemid=1", ""],        
    ["core", "/components/com_search/", ""],        
    ["core", "/components/com_admin/admin.admin.html.php?mosConfig_absolute_path=a", ""],        
    ["core", "/administrator/components/com_admin/admin.admin.html.php?mosConfig_absolute_path=a", ""],        
    ["core", "/index.php?option=com_mailto&tmpl=mailto&article=1&Itemid=1", ""],        
    ["core", "/index.php?option=com_content&view=a&id=25&Itemid=28", ""],        
    ["core", "/index.php?option=com_content&view=archive", "filter=1&month=1&year=2011"],        
    ["core", "/administrator/components/com_installer/", ""],        
    ["core", "/components/com_search/", ""],        
    ["core", "/index.php?option=com_poll&task=results&id=14&mosmsg=a", ""],        
    ["core", "/index.php?option=com_banners&task=archivesection&id=1", ""],        
    ["core", "/templates/be2004-2/index.php?mosConfig_absolute_path=a", ""],        
    ["core", "/modules/mod_as_category/mod_as_category.php?mosConfig_absolute_path=", ""],        
    ["core", "/modules/mod_quick_question.php", ""],        
    ["core", "/modules/mod_pxt/mod_pxt_latest.php?GLOBALS[mosConfig_absolute_path]=a", ""],        
    ["core", "/modules/mod_calendar.php?absolute_path=a", ""],     
    ["com_shoutbox", "/index.php?option=com_shoutbox&controller=a", ""],       
    ["com_weblinks", "/index.php?option=com_weblinks&view=category&id=2:joomla-specific-links&limit=10&filter_order_Dir=&filter_order=", ""],
    ["com_a6mambocredits", "/components/com_a6mambocredits/admin.a6mambocredits.php?mosConfig_absolute_path=", ""],
    ["com_a6mambohelpdesk", "/components/com_a6mambohelpdesk/admin.a6mambohelpdesk.php?mosConfig_live_site=", ""],
    ["com_advancedpoll", "/", ""],
    ["com_akocomment", "/", "acname=1&contentid=1"],
    ["com_articles", "/classes/html/com_articles.php?absolute_path=", ""],
    ["com_artlinks", "/components/com_artlinks/artlinks.dispnew.php?mosConfig_absolute_path=", ""],
    ["com_trade", "/", ""],
    ["com_bayesiannaivefilter", "/components/com_bayesiannaivefilter/lang.php?mosConfig_absolute_path=", ""],
    ["com_babackup", "/components/com_babackup/classes/Tar.php?mosConfig_absolute_path=", ""],
    ["com_bsqsitestats", "/", ""], 
    ["com_resman", "/index.php?option=com_resman&task=moreinfo&id=1", ""],
    ["com_classifieds", "/", ""],
    ["com_colophon", "/components/com_colophon/admin.colophon.php?mosConfig_absolute_path=", ""],
    ["com_profiler", "/index.php?option=com_profile&Itemid=42&task=&task=viewoffer&oid=1", ""],
    ["com_events", "/", ""],
    ["com_expose", "/components/com_expose/uploadimg.php", ""],
    ["com_extcalendar", "/index.php?option=com_extcalendar&Itemid=42&month=1&year=2011&prev=1", ""],
    ["com_facileforms", "/index.php?option=com_facileforms&Itemid=640&user_id=107&catid=1", ""],
    ["com_galleria", "/components/com_galleria/galleria.html.php?mosConfig_absolute_path=", ""],
    ["com_gmaps", "/index.php?option=com_gmaps&task=viewmap&Itemid=57&mapId=1", ""],
    ["com_hashcash", "/components/com_hashcash/server.php?mosConfig_absolute_path=", ""],
    ["com_hotproperty", "/", ""],
    ["com_jce", "/components/com_jce/jce.php?img=1&title=2&w=3&h=4", ""],
    ["com_jpack", "/components/com_jpack/includes/CAltInstaller.php?mosConfig_absolute_path=", ""],
    ["com_joomlaboard", "/components/com_joomlaboard/file_upload.php?sbp=", ""],
    ["com_joomlalib", "/", ""],
    ["com_jd-wp", "/", ""],
    ["com_fundraiser", "/", ""],
    ["com_marketplace", "/index.php?option=com_marketplace&page=show_category&catid=1", ""],
    ["com_neoreferences", "/index.php?option=com_neoreferences&Itemid=27&catid=1", ""],
    ["com_chronocontact", "/components/com_chronocontact/excelwriter/PPS/File.php?mosConfig_absolute_path=", ""],
    ["com_mambospgm", "/", ""],
    ["com_ajaxchat", "/", ""],
    ["com_cloner", "/", ""],
    ["com_quiz", "/index.php?option=com_quiz&task=user_tst_shw&Itemid=61&tid=1", ""],
    ["com_mcquiz", "/index.php?option=com_mcquiz&task=user_tst_shw&Itemid=42&tid=1", ""],
    ["com_paxxgallery", "/index.php?option=com_paxxgallery&Itemid=85&gid=7&userid=1&task=view&iid=1&Itemid=85&gid=7&userid=1&task=view&iid=1", ""],
    ["com_pcchess", "/components/com_pcchess/include.pcchess.php?mosConfig_absolute_path=", ""],
    ["com_xfaq", "/index.php?option=com_xfaq&task=answer&Itemid=27&catid=97&aid=1", ""],
    ["com_rapidrecipe", "/index.php?option=com_rapidrecipe&page=viewrecipe&recipe_id=1", ""],
    ["com_doc", "/index.php?option=com_doc&task=view&sid=1", ""],
    ["com_noticias", "/index.php?option=com_noticias&Itemid=xcorpitx&task=detalhe&id=1", ""],
    ["com_neogallery", "/index.php?option=com_neogallery&task=show&Itemid=5&catid=1", ""],
    ["com_ynews", "/index.php?option=com_ynews&Itemid=0&task=showYNews&id=1", ""],
    ["com_jooget", "/index.php?option=com_jooget&Itemid=61&task=detail&id=1", ""],
    ["com_mediaslide", "/index.php?option=com_mediaslide&act=contact&id=1&albumnum=1&act=contact&id=1&albumnum=1", ""],
    ["com_rssxt", "/components/com_rssxt/rssxt.php?mosConfig_absolute_path=", ""],
    ["com_ezine", "/", ""],
    ["com_productshowcase", "/index.php?option=com_productshowcase&Itemid=1&action=details&id=1", ""],
    ["com_candle", "/index.php?option=com_candle&task=content&cID=1", ""],
    ["com_simpleshop", "/index.php?option=com_simpleshop&task=browse&Itemid=29&catid=1", ""],
    ["com_hwdvideoshare", "/index.php?option=com_hwdvideoshare&func=viewcategory&Itemid=61&cat_id=1", ""],
    ["com_clasifier", "/index.php?option=com_clasifier&Itemid=61&cat_id=1", ""],
    ["com_pccookbook", "/index.php?option=com_pccookbook&page=viewuserrecipes&user_id=1", ""],
    ["com_astatspro", "/components/com_astatspro/refer.php?id=1", ""],
    ["com_galeria", "/index.php?option=com_galeria&Itemid=61&func=detail&id=1", ""],
    ["com_fm", "/components/com_fm/fm.install.php?lm_absolute_path=", ""],
    ["com_serverstat", "/components/com_serverstat/install.serverstat.php?mosConfig_absolute_path=", ""],
    ["com_comprofiler", "/index.php?option=com_comprofiler&task=userProfile&user=1&task=userProfile&user=1", ""],
    ["com_cropimage", "/components/com_cropimage/admin.cropcanvas.php?cropimagedir=", ""],
    ["com_mambatstaff", "/components/com_mambatstaff/mambatstaff.php?mosConfig_absolute_path=", ""],
    ["com_loudmouth", "/", ""],
    ["com_forum", "/components/com_forum/download.php?phpbb_root_path=", ""],
    ["com_kochsuite", "/components/com_kochsuite/config.kochsuite.php?mosConfig_absolute_path=", ""],
    ["com_remository", "/components/com_remository/admin.remository.php?mosConfig_absolute_path=", ""],
    ["com_minibb", "/components/minibb/index.php?absolute_path=", ""],
    ["com_moodle", "/components/com_moodle/moodle.php?mosConfig_absolute_path=", ""],
    ["com_cpg", "/components/com_cpg/cpg.php?mosConfig_absolute_path=", ""],
    ["com_phpshop", "/components/com_phpshop/toolbar.phpshop.html.php?mosConfig_absolute_path=", ""],
    ["com_mambowiki", "/components/com_mambowiki/MamboLogin.php?IP=", ""],
    ["com_lurm_constructor", "/components/com_lurm_constructor/admin.lurm_constructor.php?lm_absolute_path=", ""],
    ["com_flippingbook", "/index.php?option=com_flippingbook&Itemid=28&book_id=1", ""],
    ["com_extplorer", "/index.php?com_extplorer-test1", ""],
    ["com_joomlaxplorer", "/index.php?option=com_joomlaxplorer&action=show_error&dir=..%2F..%2F..%2F%2F..%2F..%2Fetc", ""],
    ["com_joomlaxplorer", "/index.php?option=com_joomlaxplorer&action=show_error&dir=hsmx&order=name&srt=yes&error=a", ""],
    ["com_onlineflashquiz", "/component/com_onlineflashquiz/quiz/common/db_config.inc.php?base_dir=", ""],
    ["com_actualite", "/index.php?option=com_actualite&task=edit&id=1", ""],
    ["com_myalbum", "/index.php?option=com_myalbum&album=1", ""],
    ["com_alphacontent", "/index.php?option=com_alphacontent&section=6&cat=15&task=view&id=1", ""],
    ["com_cinema", "/index.php?option=com_cinema&Itemid=1&func=detail&id=1", ""],
    ["com_d3000", "/index.php?option=com_d3000&task=showarticles&id=1", ""],
    ["com_rekry", "/index.php?option=com_rekry&Itemid=60&rekryview=view&op_id=1", ""],
    ["com_custompages", "/index.php?option=com_custompages&cpage=", ""],
    ["com_restaurante", "/index.php?option=com_restaurante&task=detail&Itemid=1&id=1", ""],
    ["com_alberghi", "/index.php?option=com_alberghi&task=detail&Itemid=1&id=1", ""],
    ["com_joovideo", "/index.php?option=com_joovideo&Itemid=1&task=detail&id=1", ""],
    ["com_acajoom", "/index.php?option=com_acajoom&act=mailing&task=view&listid=1&Itemid=1&mailingid=1", ""],
    ["com_jreviews", "/components/com_jreviews/scripts/xajax.inc.php?mosConfig_absolute_path=", ""],
    ["com_bsq_sitestats", "/", ""],
    ["com_madeira", "/components/com_madeira/img.php?url=", ""],
    ["com_mmp", "/components/com_mmp/help.mmp.php?mosConfig_absolute_path=", ""],
    ["com_extended_registration", "/components/com_extended_registration/registration_detailed.inc.php?mosConfig_absolute_path=", ""],
    ["com_sef", "/", ""],
    ["com_multibanners", "/components/com_multibanners/extadminmenus.class.php?mosConfig_absolute_path=", ""],
    ["com_mospray", "/components/com_mospray/scripts/admin.php?basedir=", ""],
    ["com_mosmedia", "/components/com_mosmedia/media.tab.php?mosConfig_absolute_path=", ""],
    ["com_mtree", "/components/com_mtree/Savant2/Savant2_Plugin_textarea.php?mosConfig_absolute_path=", ""],
    ["com_mgm", "/components/com_mgm/help.mgm.php?mosConfig_absolute_path=", ""],
    ["com_mambelfish", "/components/com_mambelfish/mambelfish.class.php?mosConfig_absolute_path=", ""],
    ["com_lmo", "/components/com_lmo/lmo.php?mosConfig_absolute_path=", ""],
    ["com_linkdirectory", "/components/com_linkdirectory/toolbar.linkdirectory.html.php?mosConfig_absolute_path=", ""],
    ["mod_letterman", "/", ""],
    ["com_jim", "/components/com_jim/install.jim.php?mosConfig_absolute_path=", ""],
    ["com_jd-wiki", "/components/com_jd-wiki/lib/tpl/default/main.php?mosConfig_absolute_path=", ""],
    ["com_joomla-visites", "/components/com_joomla-visites/core/include/myMailer.class.php?mosConfig_absolute_path=", ""],
    ["com_jpad", "/index.php?option=com_jpad&task=edit&Itemid=39&cid=1", ""],
    ["com_filiale", "/index.php?option=com_filiale&idFiliale=1", ""],
    ["com_ponygallery", "/index.php?option=com_ponygallery&Itemid=x&func=viewcategory&catid=1", ""],
    ["com_joomlaradiov5", "/components/com_joomlaradiov5/admin.joomlaradiov5.php?mosConfig_live_site=", ""],
    ["com_slideshow", "/components/com_slideshow/admin.slideshow1.php?mosConfig_live_site=", ""],
    ["com_zoom", "/components/com_zoom/classes/database.php?mosConfig_absolute_path=", ""],
    ["com_virtuemart", "/index.php?option=com_contact&Itemid=1", ""],
    ["com_uhp2", "/components/com_uhp2/uhp_config.php?mosConfig_absolute_path=", ""],
    ["com_uhp", "/components/com_uhp/uhp_config.php?mosConfig_absolute_path=", ""],
    ["com_thopper", "/components/com_thopper/inc/contact_type.php?mosConfig_absolute_path=", ""],
    ["com_securityimages", "/components/com_securityimages/lang.php?mosConfig_absolute_path=", ""],
    ["com_utchat", "/components/com_utchat/pfc/lib/pear/PHPUnit/GUI/Gtk.php?file=", ""],
    ["com_simpleboard", "/components/com_simpleboard/file_upload.php?sbp=", ""],
    ["com_smf", "/components/com_smf/smf.php?mosConfig_absolute_path=", ""],
    ["com_rwcards", "/index.php?option=com_rwcards&task=listCards&category_id=1", ""],
    ["com_rsgallery2", "/index.php?option=com_rsgallery2&page=inline&catid=1", ""],
    ["com_pollxt", "/components/com_pollxt/conf.pollxt.php?mosConfig_absolute_path=", ""],
    ["com_peoplebook", "/components/com_peoplebook/param.peplebook.php?mosConfig_absolute_path=", ""],
    ["com_philaform", "/index.php?option=com_philaform&form_id=1", ""],
    ["com_performs", "/components/com_performs/performs.php?mosConfig_absolute_path=", ""],
    ["com_wmtportfolio", "/administrator/components/com_wmtportfolio/admin.wmtportfolio.php?mosConfig_absolute_path=", ""],
    ["com_wmtgallery", "/components/com_wmtgallery/admin.wmtgallery.php?mosConfig_live_site=", ""],
    ["com_panoramic", "/components/com_panoramic/admin.panoramic.php?mosConfig_live_site=", ""],
    ["com_videodb", "/components/com_videodb/core/videodb.class.xml.php?mosConfig_absolute_path=", ""],
    ["com_htmlarea3_xtd", "/components/com_htmlarea3_xtd-c/popups/ImageManager/config.inc.php?mosConfig_absolute_path=", ""],
    ["com_calendar", "/", ""],
    ["com_nfn_addressbook", "/", ""],
    ["com_x-shop", "/components/com_x-shop/admin.x-shop?mosConfig_absolute_path=", ""],
    ["com_tour_toto", "/", ""],
    ["com_swmenupro", "/administrator/components/com_swmenupro/ImageManager/Classes/ImageManager.php?mosConfig_absolute_path=", ""],
    ["com_nicetalk", "/index.php?option=com_nicetalk&tagid=1", ""],
    ["com_jombib", "/", ""],
    ["com_rsfiles", "/index.php?option=com_rsfiles&task=files.download&path=...index.php", ""],
    ["com_jreactions", "/components/com_jreactions/langset.php?comPath=", ""],
    ["com_lm", "/", ""],
    ["com_webring", "/components/com_webring/admin.webring.docs.php?component_dir=", ""],
    ["com_joom12pic", "/components/com_joom12pic/admin.joom12pic.php?mosConfig_live_site=", ""],
    ["com_flashfun", "/index.php?option=com_flash&act=view&Itemid=37&id=1", ""],
    ["com_neorecruit", "/index.php?option=com_neorecruit&task=offer_view&id=option=com_neorecruit&task=offer_view&id=1", ""],
    ["com_reporter", "/components/com_reporter/processor/reporter.sql.php?mosConfig_absolute_path=", ""],
    ["com_joomlaflashfun", "/components/com_joomlaflashfun/admin.joomlaflashfun.php?mosConfig_live_site=", ""],
    ["com_directory", "/index.php?option=com_directory&page=viewcat&catid=1", ""],
    ["com_puarcade", "/index.php?option=com_puarcade&Itemid=92&fid=1", ""],
    ["com_rsgallery", "/index.php?option=com_rsgallery&page=inline&catid=1", ""],
    ["com_juser", "/components/com_juser/xajax_functions.php?mosConfig_absolute_path=", ""],
    ["com_jjgallery", "/components/com_jjgallery/admin.jjgallery.php?mosConfig_absolute_path=", ""],
    ["com_colorlab", "/components/com_color/admin.color.php?mosConfig_live_site=", ""],
    ["com_joomla_flash_uploader", "/components/com_joomla_flash_uploader/install.joomla_flash_uploader.php?mosConfig_absolute_path=", ""],
    ["com_jcs", "/components/com_jcs/jcs.function.php?mosConfig_absolute_path=", ""],
    ["com_mp3_allopass", "/components/com_mp3_allopass/allopass-error.php?mosConfig_live_site=", ""],
    ["com_xsstream-dm", "/index.php?option=com_xsstream-dm&Itemid=69&movie=1", ""],
    ["com_biblestudy", "/index.php?option=com_biblestudy&view=mediaplayer&id=1", ""],
    ["com_fq", "/index.php?option=com_fq&Itemid=999&listid=1", ""],
    ["com_football", "/index.php?option=com_football&task=viewteam&teamID=1", ""],
    ["com_jabode", "/index.php?option=com_jabode&task=sign&sign=taurus&id=1", ""],
    ["com_netinvoice", "/index.php?option=com_netinvoice&action=orders&task=order&cid=1", ""],
    ["com_beamospetition", "/index.php?option=com_beamospetition&pet=1", ""],
    ["com_prayercenter", "/index2.php?option=com_prayercenter&task=view_request&id=1", ""],
    ["com_webhosting", "/index.php?option=com_webhosting&catid=1&catid=1", ""],
    ["com_datsogallery", "/", ""],    
    ["com_artist", "/index.php?option=com_artist&idgalery=1", ""],
    ["com_mycontent", "/index.php?option=com_mycontent&task=view&id=1&task=view&id=1", ""],
    ["com_joobb", "/index.php?option=com_joobb&view=forum&forum=1&view=forum&forum=1", ""],
    ["com_acctexp", "/index.php?option=com_acctexp&task=subscribe&usage=1&task=subscribe&usage=1", ""],
    ["com_joomradio", "/index.php?option=com_joomradio&page=show_video&id=1", ""],
    ["com_equotes", "/index.php?option=com_equotes&id=1", ""],
    ["com_idoblog", "/index.php?option=com_idoblog&task=userblog&userid=1", ""],
    ["com_jb2", "/index.php?option=com_jb2&view=category&CategoryID=1&view=category&CategoryID=1", ""],
    ["com_jotloader", "/index.php?option=com_jotloader&cid=1&cid=1", ""],
    ["com_easybook", "/index.php?option=com_easybook&Itemid=1&func=deleteentry&gbid=1", ""],
    ["com_joomladate", "/index.php?option=com_joomladate&task=viewProfile&user=1", ""],
    ["com_game", "/index.php?option=com_gameq&task=page&category_id=1", ""],
    ["com_n-forms", "/index.php?option=com_n-forms&form_id=1&form_id=1", ""],
    ["com_yvcomment", "/index.php?option=com_yvcomment&view=comment&ArticleID=1&view=comment&ArticleID=1", ""],
    ["com_news_portal", "/index.php?option=com_news_portal&Itemid=1&Itemid=1", ""],
    ["com_expshop", "/index.php?option=com_expshop&page=show_payment&catid=1", ""],
    ["com_xewebtv", "/index.php?option=com_xewebtv&Itemid=60&func=detail&id=1&Itemid=60&func=detail&id=1", ""],
    ["com_versioning ", "/index.php?option=com_versioning&task=edit&id=1", ""],
    ["com_mygallery", "/index.php?option=com_mygallery&func=viewcategory&cid=1", ""],
    ["com_brightweblinks", "/index.php?option=com_brightweblinks&Itemid=58&catid=1", ""],
    ["com_vr", "/index.php?option=com_vr&Itemid=78&task=viewer&room_id=1", ""],
    ["com_is", "/index.php?option=com_is&task=motor&motor=1", ""],
    ["com_altas", "/index.php?option=com_altas&mes=1", ""],
    ["com_dbquery", "/components/com_dbquery/classes/DBQ/admin/common.class.php?mosConfig_absolute_path=", ""],
    ["com_ionfiles", "/components/com_ionfiles/download.php?file=../../configuration.php&download=1 ", ""],
    ["com_dtregister", "/index.php?option=com_dtregister&eventId=1&task=pay_options&Itemid=138", ""],
    ["com_ezstore", "/index.php?option=com_ezstore&Itemid=1&func=detail&id=1&Itemid=1&func=detail&id=1", ""],
    ["com_na_qforms", "/index.php?option=com_na_qforms&QF_url=error&QF_msg=a", ""],
    ["remository", "/index.php?option=com_imagebrowser&folder=../../../../_non_", ""],
    ["com_hotspots", "/index.php?Itemid=53&option=com_hotspots&task=w&w=1", ""],
    ["com_joomtracker", "/index.php?option=com_joomtracker&task=tordetails&id=1", ""],
    ["com_ignitegallery", "/index.php?option=com_ignitegallery&task=view&gallery=1&Itemid=18 ", ""],
    ["com_mad4joomla", "/index.php?option=com_mad4joomla&jid=1", ""],
    ["com_ownbiblio", "/index.php?option=com_ownbiblio&view=catalogue&catid=1", ""],
    ["com_dailymessage", "/index.php?option=com_dailymessage&Itemid=31&page=[PAGENAME]&id=1", ""],
    ["com_ds-syndicate", "/index.php?option=ds-syndicate&version=1&feed_id=1", ""],
    ["com_thyme", "/index.php?option=com_thyme&calendar=1&category=1&d=1&m=1&y=2008&Itemid=1&event=1", ""],
    ["com_ab_gallery", "/index.php?option=com_ab_gallery&Itemid=37&gallery=_NOT_EXIST", ""],
    ["com_kbase", "/index.php?option=com_kbase&view=article&id=1", ""],
    ["{admin}com_treeg", "/administrator/components/com_treeg/admin.treeg.php?mosConfig_live_site=", ""],
    ["com_googlebase", "/components/com_googlebase/admin.googlebase.php?mosConfig_absolute_path=", ""],
    ["com_ongumatimesheet20", "/components/com_ongumatimesheet20/lib/onguma.class.php?mosConfig_absolute_path=", ""],
    ["com_pro_desk", "/index.php?option=com_pro_desk&include_file=", ""],
    ["com_clickheat", "/components/com_clickheat/Recly/common/GlobalVariables.php?GLOBALS[mosConfig_absolute_path]=", ""],
    ["com_dadamail", "/components/com_dadamail/config.dadamail.php?GLOBALS[mosConfig_absolute_path]=", ""],
    ["com_competitions", "/components/com_competitions/includes/settings/settings.php?mosConfig_absolute_path=", ""],
    ["{admin}com_peoplebook", "/administrator/components/com_peoplebook/param.peoplebook.php?mosConfig_absolute_path=", ""],
    ["com_recly", "/components/com_feederator/includes/tmsp/add_tmsp.php?mosConfig_absolute_path=", ""],
    ["com_books", "/index.php?option=com_books&task=book_details&book_id=1", ""],
    ["com_catalogproduction", "/index.php?option=com_catalogproduction&task=viewdetail&id=1", ""],
    ["com_rssreader", "/components/com_rssreader/admin.rssreader.php?mosConfig_live_site=", ""],
    ["com_hotproperties", "/", ""],
    ["com_contactinfo", "/index.php?option=com_contactinfo&catid=1", ""],
    ["{admin}com_a6mambocredits", "/administrator/components/com_a6mambocredits/admin.a6mambocredits.php?mosConfig_absolute_path=", ""],
    ["{admin}com_a6mambohelpdesk", "/administrator/components/com_a6mambohelpdesk/admin.a6mambohelpdesk.php?mosConfig_live_site=", ""],
    ["{admin}com_colophon", "/administrator/components/com_colophon/admin.colophon.php?mosConfig_absolute_path=", ""],
    ["{admin}com_comprofiler", "/administrator/components/com_comprofiler/plugin.class.php?mosConfig_absolute_path=", ""],
    ["{admin}com_mambelfish", "/administrator/components/com_mambelfish/mambelfish.class.php?mosConfig_absolute_path=", ""],
    ["{admin}com_comprofiler", "/index.php?option=com_comprofiler&task=userProfile&user=1&task=userProfile&user=1", ""],
    ["{admin}com_uhp2", "/administrator/components/com_uhp2/uhp_config.php?mosConfig_absolute_path=", ""],
    ["{admin}com_uhp", "/administrator/components/com_uhp/uhp_config.php?mosConfig_absolute_path=", ""],
    ["{admin}com_bayesiannaivefilter", "/administrator/components/com_bayesiannaivefilter/lang.php?mosConfig_absolute_path=", ""],
    ["{admin}com_webring", "/administrator/components/com_webring/admin.webring.docs.php?component_dir=", ""],
    ["{admin}com_jim", "/administrator/components/com_jim/install.jim.php?mosConfig_absolute_path=", ""],
    ["{admin}com_mgm", "/administrator/components/com_mgm/help.mgm.php?mosConfig_absolute_path=", ""],
    ["{admin}com_linkdirectory", "/administrator/components/com_linkdirectory/toolbar.linkdirectory.html.php?mosConfig_absolute_path=", ""],
    ["{admin}com_kochsuite", "/administrator/components/com_kochsuite/config.kochsuite.php?mosConfig_absolute_path=", ""],
    ["{admin}com_swmenupro", "/administrator/components/com_swmenupro/ImageManager/Classes/ImageManager.php?mosConfig_absolute_path=", ""],
    ["{admin}com_jpack", "/administrator/components/com_jpack/includes/CAltInstaller.php?mosConfig_absolute_path=", ""],
    ["{admin}com_joomlaradiov5", "/administrator/components/com_joomlaradiov5/admin.joomlaradiov5.php?mosConfig_live_site=", ""],
    ["{admin}com_joomlaflashfun", "/administrator/components/com_joomlaflashfun/admin.joomlaflashfun.php?mosConfig_live_site=", ""],
    ["{admin}com_jcs", "/administrator/components/com_jcs/jcs.function.php?mosConfig_absolute_path=", ""],
    ["{admin}com_joomla_flash_uploader", "/administrator/components/com_joomla_flash_uploader/install.joomla_flash_uploader.php?mosConfig_absolute_path=", ""],
    ["{admin}com_mosmedia", "/administrator/components/com_mosmedia/media.tab.php?mosConfig_absolute_path=", ""],
    ["{admin}com_wmtgallery", "/administrator/components/com_wmtgallery/admin.wmtgallery.php?mosConfig_live_site=", ""],
    ["{admin}com_wmtportfolio", "/administrator/components/com_wmtportfolio/admin.wmtportfolio.php?mosConfig_absolute_path=", ""],
    ["{admin}com_colorlab", "/administrator/components/com_color/admin.color.php?mosConfig_live_site=", ""],
    ["{admin}com_jjgallery", "/administrator/components/com_jjgallery/admin.jjgallery.php?mosConfig_absolute_path=", ""],
    ["{admin}com_juser", "/administrator/components/com_juser/xajax_functions.php?mosConfig_absolute_path=", ""],
    ["{admin}com_extplorer", "/index.php?com_extplorer-test1", ""],
    ["{admin}com_joom12pic", "/administrator/components/com_joom12pic/admin.joom12pic.php?mosConfig_live_site=", ""],
    ["{admin}com_panoramic", "/administrator/components/com_panoramic/admin.panoramic.php?mosConfig_live_site=", ""],
    ["com_comprofiler", "/components/com_comprofiler/plugin.class.php?mosConfig_absolute_path=", ""],
    ["com_djiceshoutbox", "/index.php?option=com_djiceshoutbox&view=ajax&format=djiceshoutbox", ""],
    ["com_flyspray", "/components/com_flyspray/startdown.php?file=", ""],
    ["com_extcalendar", "/components/com_extcalendar/extcalendar.php?mosConfig_absolute_path=", ""],
    ["com_pccookbook", "/components/com_pccookbook/pccookbook.php?mosConfig_absolute_path=", ""],
    ["com_smf", "/components/com_smf/smf.php?mosConfig_absolute_path=", ""],
    ["com_loudmounth", "/components/com_loudmounth/includes/abbc/abbc.class.php?mosConfig_absolute_path=", ""],
    ["{admin}com_multibanners", "/administrator/components/com_multibanners/extadminmenus.class.php?mosConfig_absolute_path=", ""],
    ["com_cmimarketplace", "/index.php?option=com_cmimarketplace&Itemid=1&viewit=/../../&cid=1", ""],
    ["core", "/akocomments.php?mosConfig_absolute_path=", ""],
    ["{admin}com_cropimage", "/administrator/components/com_cropimage/admin.cropcanvas.php?cropimagedir=", ""],
    ["{admin}com_serverstat", "/administrator/components/com_serverstat/install.serverstat.php?mosConfig_absolute_path=", ""],
    ["com_ijoomla_archive", "/index.php?option=com_ijoomla_archive&task=archive&search_archive=1&act=search&catid=1&task=archive&search_archive=1&act=search&catid=1", ""],
    ["{admin}com_remository", "/administrator/components/com_remository/admin.remository.php?mosConfig_absolute_path=", ""],
    ["{admin}com_lurm_constructor", "/administrator/components/com_lurm_constructor/admin.lurm_constructor.php?lm_absolute_path=", ""],
    ["com_digistore", "/index.php?option=com_digistore&task=show_product&pid=1&task=show_product&pid=1", ""],
    ["{admin}com_phpshop", "/administrator/components/com_phpshop/toolbar.phpshop.html.php?mosConfig_absolute_path=", ""],
    ["com_maianmusic", "/index.php?option=com_maianmusic&section=category&category=1&Itemid=1", ""],
    ["{admin}com_mmp", "/administrator/components/com_mmp/help.mmp.php?mosConfig_absolute_path=", ""],
    ["com_bsq_sitestats", "/components/com_bsq_sitestats/external/rssfeed.php?baseDir=", ""],
    ["{admin}com_chronocontact", "/administrator/components/com_chronocontact/excelwriter/PPS/File.php?mosConfig_absolute_path=", ""],
    ["com_feederator", "/components/com_feederator/includes/tmsp/add_tmsp.php?mosConfig_absolute_path=", ""],
    ["{admin}com_feederator", "/administrator/components/com_feederator/includes/tmsp/add_tmsp.php?mosConfig_absolute_path=", ""],
    ["com_bookjoomlas", "/index.php?option=com_bookjoomlas&Itemid=1&func=comment&gbid=1", ""],
    ["com_gameq", "/index.php?option=com_gameq&task=page&category_id=1", ""],
    ["{admin}com_astatspro", "/administrator/components/com_astatspro/refer.php?id=1", ""],
    ["com_prayercenter", "/index.php?option=com_prayercenter&task=view_request&id=1", ""],
    ["com_pcchess", "/index.php?option=com_pcchess&Itemid=61&page=players&user_id=1", ""],
    ["com_garyscookbook", "/index.php?option=com_garyscookbook&Itemid=21&func=detail&id=1", ""],
    ["com_hello_world", "/index.php?option=com_hello_world&Itemid=27&task=show&type=intro&id=1", ""],
    ["com_cms", "/index.php?option=com_cms&act=viewitems&cat_id=1", ""],
    ["com_most", "/index.php?option=com_most&mode=email&secid=1", ""],
    ["com_idvnews", "/index.php?option=com_idvnews&id=1", ""],
    ["com_joomlavvz", "/index.php?option=com_joomlavvz&Itemid=34&func=detail&id=1", ""],
    ["com_referenzen", "/index.php?option=com_referenzen&Itemid=7&detail=1", ""],
    ["com_genealogy", "/index.php?option=com_genealogy&task=profile&id=1", ""],
    ["com_listoffreeads", "/index.php?option=com_listoffreeads&AdId=1", ""],
    ["com_geoboerse", "/index.php?option=com_geoboerse&page=view&catid=1", ""],
    ["com_ricette", "/index.php?option=com_ricette&Itemid=1&func=detail&id=1", ""],
    ["com_team", "/index.php?option=com_team&gid=1", ""],
    ["com_formtool", "/index.php?option=com_formtool&task=view&formid=2&catid=1", ""],
    ["com_sg", "/index.php?option=com_sg&Itemid=16&task=order&range=3&category=3&pid=1", ""],
    ["com_faq", "/index.php?option=faq&task=viewallfaq&catid=1", ""],
    ["com_omnirealestate", "/index.php?option=com_omnirealestate&Itemid=0&func=showObject&info=contact&objid=1&results=joomla", ""],
    ["com_model", "/index.php?option=com_model&Itemid=0&task=pipa&act=2&objid=1", ""],
    ["com_mezun", "/index.php?option=com_mezun&task=edit&hidemainmenu=joomla&id=1", ""],
    ["com_ewriting", "/index.php?option=com_ewriting&Itemid=9999&func=SELECTcat&cat=1", ""],
    ["com_livechat", "/components/com_livechat/getSavedChatRooms.php?chat=0&last=1", ""],
    ["{admin}com_livechat", "/administrator/components/com_livechat/getSavedChatRooms.php?chat=0&last=1", ""],
    ["com_letterman", "/index.php?option=com_letterman&task=view&Itemid=&mosConfig_absolute_path=", ""],
    ["com_livechat", "/components/com_livechat/xmlhttp.php", ""],
    ["{admin}com_livechat", "/administrator/components/com_livechat/xmlhttp.php", ""],
    ["com_mydyngallery", "/index.php?option=com_mydyngallery&directory=a", ""],
    ["com_jmovies", "/index.php?option=com_jmovies&Itemid=29&task=detail&id=1", ""],
    ["com_tech_article", "/index.php?option=com_tech_article&task=item&Itemid=17&item=1", ""],
    ["com_hbssearch", "/index.php?option=com_hbssearch&task=showhoteldetails&id=4&chkin=2008-08-15&chkout=2008-08-18&datedif=3&str_day=Fri&end_day=Mon&start_day=&star=&child1=0&adult1=1&Itemid=54&r_type=1&task=showhoteldetails&id=4&chkin=2008-08-15&chkout=2008-08-18&datedif=3&str_day=Fri&end_day=Mon&start_day=&star=&child1=0&adult1=1&Itemid=54&r_type=1", ""],
    ["com_tophotelmodule", "/index.php?option=com_tophotelmodule&task=showhoteldetails&id=1&task=showhoteldetails&id=1", ""],
    ["com_volunteer", "/index.php?option=com_volunteer&task=jobs&act=jobshow&Itemid=29&orgs_id=3&job_id=1&filter=&city_id=&function_id=&limit=5&pageno=1", ""],
    ["com_lowcosthotels", "/index.php?option=com_lowcosthotels&task=showhoteldetails&id=1&task=showhoteldetails&id=1", ""],
    ["com_allhotels", "/index.php?option=com_allhotels&task=showhoteldetails&id=1&task=showhoteldetails&id=1", ""],
    ["com_ice", "/index.php?option=com_ice&catid=1&catid=1", ""],
    ["com_liveticker", "/index.php?option=com_liveticker&task=viewticker&tid=1&task=viewticker&tid=1", ""],
    ["com_mdigg", "/index.php?option=com_mdigg&act=story_lists&task=view&category=1", ""],
    ["com_5starhotels", "/index.php?option=com_5starhotels&task=showhoteldetails&id=1", ""],
    ["com_paxgallery", "/index.php?option=com_paxgallery&task=table&gid=1&task=table&gid=1", ""],
    ["com_na_content", "/index.php?option=com_na_content&task=view&id=1&task=view&id=1", ""],
    ["com_na_mydocs", "/index.php?option=com_na_mydocs&task=showerr&errmsg=Your%20site%20has%20been%20hacked!", ""],
    ["com_simple_review", "/index.php?option=com_simple_review&category=1", ""],
    ["com_na_newsdescription", "/index.php?option=com_na_newsdescription&task=show&groupId=17377_19&newsid=1", ""],
    ["com_phocadocumentation", "/index.php?option=com_phocadocumentation&view=section&id=1", ""],
    ["com_xevidmegahd", "/index.php?option=com_xevidmegahd&Itemid=99999&func=viewcategory&catid=1", ""],
    ["com_jashowcase", "/index.php?option=com_jashowcase&view=jashowcase&Itemid=109&catid=1", ""],
    ["com_newsflash", "/index.php?option=com_newsflash&catid=0&id=1", ""],
    ["com_portfol", "/index.php?option=com_portfol&Itemid=814&task=viewcategory&vcatid=1", ""],
    ["com_gigcal", "/index.php?option=com_gigcal&task=details&gigcal_gigs_id=1&Itemid=37", ""],
    ["com_gigcal", "/index.php?option=com_gigcal&Itemid=78&id=1", ""],
    ["com_camelcitydb2", "/index.php?option=com_camelcitydb2&id=1&view=detail&Itemid=15", ""],
    ["com_fantasytournament", "/index.php?option=com_fantasytournament&Itemid=&func=managersByManager&managerID=1", ""],
    ["com_rdautos", "/index.php?option=com_rdautos&view=category&id=1&Itemid=54", ""],
    ["com_news", "/index.php?option=com_news&id=1", ""],
    ["com_prod", "/index.php?option=com_prod&task=products&cid=1", ""],
    ["com_beamospetition", "/index.php?option=com_beamospetition&func=sign&pet=a", ""],
    ["com_beamospetition", "/index.php?option=com_beamospetition&func=sign&mpid=1", ""],
    ["com_flashmagazinedeluxe", "/index.php?option=com_flashmagazinedeluxe&Itemid=10&task=magazine&mag_id=1", ""],
    ["com_pcchess", "/index.php?option=com_pcchess&Itemid=84&page=showgame&game_id=1&Itemid=84&page=showgame&game_id=1", ""],
    ["com_pccookbook", "/index.php?option=com_pccookbook&page=viewrecipe&recipe_id=1&Itemid=84&page=showgame&game_id=1", ""],
    ["com_waticketsystem", "/index.php?option=com_waticketsystem&act=category&catid=1&act=category&catid=1", ""],
    ["com_eventing", "/index.php?option=com_eventing&catid=1&catid=1", ""],
    ["com_sitemap", "/components/com_sitemap/sitemap.xml.php?mosConfig_absolute_path=", ""],
    ["com_rss", "/index2.php?option=com_rss&feed=test", ""],
    ["com_Jambook", "/components/com_Jambook/jambook.php?mosConfig_absolute_path=", ""],
    ["com_akogallery", "/index.php?option=com_akogallery&Itemid=1&func=detail&id=1", ""],
    ["com_gsticketsystem", "/index.php?option=com_gsticketsystem&controller=entrypoint&task=viewCategory&catid=1&controller=entrypoint&task=viewCategory&catid=1", ""],
    ["com_casino_blackjack", "/index.php?option=com_casino_blackjack&game_mode=Blackjack&shuffle=1&Itemid=1", ""],
    ["com_casinobase", "/index.php?option=com_casinobase&Itemid=1", ""],
    ["com_casino_videopoker", "/index.php?option=com_casino_videopoker&Itemid=1", ""],
    ["com_agoragroup", "/index.php?option=com_agoragroup&con=groupdetail&id=1&con=groupdetail&id=1", ""],
    ["com_jvideo", "/index.php?option=com_jvideo&view=user&user_id=1", ""],
    ["com_seminar", "/index.php?option=com_seminar&task=View_seminar&id=1&task=View_seminar&id=1", ""],
    ["com_omphotogallery", "/index.php?option=com_omphotogallery&controller=", ""],
    ["com_artforms", "/components/com_artforms/assets/captcha/includes/captchaform/imgcaptcha.php?mosConfig_absolute_path=", ""],
    ["com_bsadv", "/index.php?option=com_bsadv&controller=peruse&task=event&id=1", ""],
    ["com_rsgallery2", "/components/com_rsgallery2/", ""],
    ["com_agora", "/index.php?option=com_agora&task=upload", ""],
    ["com_agora", "/components/com_agora/img/members/0/", ""],
    ["com_juser", "/index.php?option=com_juser&task=show_profile&id=1", ""],
    ["com_mosres", "/index.php?option=com_mosres&task=viewproperty&property_uid=1", ""],
    ["com_school", "/index.php?option=com_school&Itemid=null&func=showclass&classid=1", ""],
    ["com_moofaq", "/components/com_moofaq/includes/file_includer.php?gzip=0&file=", ""],
    ["com_portafolio", "/index.php?option=com_portafolio&task=viewcat&cid=1&Itemid=5", ""],
    ["com_booklibrary", "/com_booklibrary/toolbar_ext.php?mosConfig_absolute_path=", ""],
    ["com_media_library", "/com_media_library/toolbar_ext.php?mosConfig_absolute_path=", ""],
    ["com_realestatemanager", "/com_realestatemanager/toolbar_ext.php?mosConfig_absolute_path=", ""],
    ["com_vehiclemanager", "/com_vehiclemanager/toolbar_ext.php?mosConfig_absolute_path=", ""],
    ["com_projectfork", "/index.php?option=com_projectfork&section=", ""],
    ["com_ijoomla_rss", "/index.php?option=com_ijoomla_rss&act=xml&cat=1&act=xml&cat=1", ""],
    ["com_jumi", "/index.php?option=com_jumi&fileid=1&fileid=1", ""],
    ["com_tickets", "/index.php?option=com_tickets&task=form&id=1", ""],
    ["com_pinboard", "/components/com_pinboard/popup/popup.php?option=showupload", ""],
    ["com_amocourse", "/index.php?option=com_amocourse&task=view&view=category&catid=1", ""],
    ["com_pinboard", "/index.php?option=com_pinboard&Itemid=1&action=showpic&task=1", ""],
    ["com_bookflip", "/index.php?option=com_bookflip&book_id=1", ""],
    ["com_k2", "/index.php?option=com_k2&view=itemlist&category=a", ""],
    ["com_php", "/index.php?option=com_php&Itemid=1&id=1&Itemid=1&id=1", ""],
    ["mod_letterman", "/index.php?option=com_letterman&task=view&id=1&Itemid=1", ""],
    ["com_googlebase", "/components/com_googlebase/admin.googlebase.php?mosConfig_absolute_path=", ""],
    ["{admin}com_googlebase", "/administrator/components/com_googlebase/admin.googlebase.php?mosConfig_absolute_path=", ""],
    ["{admin}com_jreactions", "/administrator/components/com_jreactions/langset.php?comPath=", ""],
    ["com_lm", "/index.php?option=com_lms&task=showTests&cat=1", ""],
    ["com_akobook", "/", ""], 
    ["com_akobook", "/index.php?option=com_akobook&func=sign", "gbmail=1&gbpage=2"],
    ["com_propertylab", "/index.php?option=com_propertylab&task=propertysearch&type=forsale&minprice=1&start=0&perpage=20&auction_id=1", ""],
    ["com_mailarchive", "/index.php?option=com_mailarchive&Itemid=212&view=EXP&perpage=20&revdate=on&datestart=&dateend=&author=a&subject=a&exactsubject=a&search=&submit=Apply", ""],
    ["com_journal", "/index.php?option=com_journal&Itemid=213&page=index&journal=default&view=FULL&logfile=ALL&icon=ALL&version=ALL&buildstart=&buildend=&perpage=20&search=a&find=Find", ""],
    ["com_simplefaq", "/index.php?option=com_simplefaq&task=answer&Itemid=9999&catid=9999&aid=1", ""],
    ["com_gallery", "/index.php?option=com_gallery&Itemid=0&func=detail&id=1", ""],
    ["com_category", "/index.php?option=com_category&id=12&task=view&color=3&cat_id=1", ""],
    ["com_jobline", "/index.php?option=com_jobline&task=results&Itemid=&search=1&task=results&Itemid=&search=1", ""],
    ["com_knowledgebase", "/fckeditor/fckeditor.js", ""],
    ["{admin}com_x-shop", "/administrator/components/com_x-shop/admin.x-shop?mosConfig_absolute_path=", ""],
    ["com_thopper", "/com_thopper/inc/contact_type.php?mosConfig_absolute_path=", ""],
    ["com_asortyment", "/index.php?option=com_asortyment&Itemid=36&lang=pl&task=kat&katid=1", ""],
    ["com_awesom", "/index.php?option=com_awesom&Itemid=99&task=viewlist&listid=1", ""],
    ["com_be_it_easypartner", "/components/com_be_it_easypartner/be_it_easypartner.ajax.php?mosConfig_absolute_path=", ""],
    ["com_blog", "/index.php?option=com_blog&name=aria-Security.Net&task=view&pid=a", ""],
    ["com_activities", "/index.php?option=com_activities&Itemid=51&func=detail&id=1", ""],
    ["com_catalogshop", "/index.php?option=com_catalogshop&Itemid=99&func=detail&id=1", ""],
    ["com_guide", "/index.php?option=com_guide&category=1", ""],
    ["com_ clickheat", "/index.php?option=com_clickheat&task=", ""],
    ["com_clickheat", "/index.php?option=com_clickheat&task=a", ""],
    ["com_cx", "/index.php?option=com_cx&task=showrating&user_id=1", ""],
    ["com_eventlist", "/index.php?option=com_eventlist&func=details&did=1", ""],
    ["com_estateagent", "/index.php?option=com_estateagent&Itemid=99&func=showObject&info=contact&objid=1&results=null", ""],
    ["com_downloads", "/index.php?option=com_downloads&Itemid=99&func=selectcat&cat=1", ""],
    ["com_detail", "/index.php?option=com_detail&Itemid=99&id=1&Itemid=null&func=selectcat&cat=1", ""],
    ["com_datsogallery", "/index.php?option=com_datsogallery&func=detail&id=1", ""],
    ["{admin}com_dadamail", "/administrator/components/com_dadamail/config.dadamail.php?GLOBALS[mosConfig_absolute_path]=", ""],
    ["com_facileforms", "/components/com_facileforms/facileforms.frame.php?ff_compath=", ""],
    ["com_foevpartners", "/index.php?option=com_listoffreeads&AdId=1", ""],
    ["com_inter", "/index.php?option=com_inter&op=The-0utl4wz&id=1", ""],
    ["com_emcomposer", "/", ""],
    ["com_ixxocart", "/index.php?option=com_ixxocart&Itemid=1&p=catalog&parent=1&pg=1", ""],
    ["com_publication", "/index.php?option=com_publication&task=view&pid=1", ""],
    ["com_lexikon", "/index.php?option=com_lexikon&id=1", ""],
    ["com_filebase", "/index.php?option=com_filebase&Itemid=-999&func=selectfolder&filecatid=1", ""],
    ["com_aclassf", "/index.php?option=com_aclassf&Itemid=26&ct=merch5&md=details&id=1&Itemid=26&ct=merch5&md=details&id=1", ""],
    ["com_aclassf", "/index.php?option=com_aclassf&Itemid=53&ct=manw_repl&md=add_form&replid=1&Itemid=53&ct=manw_repl&md=add_form&replid=1", ""],
    ["com_aclassf", "/components/com_aclassf/gmap.php?addr=a", ""],
    ["com_joomloads", "/index.php?option=com_joomloads&view=package&Itemid=2&packageId=1", ""],
    ["com_kunena", "/index.php?option=com_kunena&Itemid=-3&func=1&Itemid=-3&func=1", ""],
    ["com_svmap","/index.php?option=com_svmap&controller=1",""],        
    ["com_myblog","/index.php?option=com_myblog&Itemid=12&task=1",""],        
    ["com_misterestate", "/index.php?option=com_misterestate&act=mesearch&task=showMESR&tmpl=component&src_cat=0&country=no&state=no&town=no&district=no&mesearch=Start+Search&searchstring=1&act=mesearch&task=showMESR&tmpl=component&src_cat=0&country=no&state=no&town=no&district=no&mesearch=Start+Search&searchstring=1", ""],
    ["com_joomgalaxy", "/index.php?option=com_joomgalaxy&view=categorylist&type=thumbnail&lang=en&catid=1", ""],
    ["com_spidercalendar", "/index.php?option=com_spidercalendar&date=1", ""],
    ["com_tag", "/index.php?option=com_tag&task=tag&lang=es&tag=1", ""],
    ["com_commedia", "/index.php?option=com_commedia&format=raw&task=down&pid=59&id=1", ""],
    ["com_discussions", "/index.php?option=com_discussions&view=thread&catid=0&thread=1", ""],
    ["com_question", "/index.php?option=com_question&catID=1", ""],
    ["com_b2portfolio", "/index.php?option=com_b2portfolio&c=1", ""],
    ["com_people", "/index.php?option=com_people&controller=people&task=details&id=1", ""],
    ["com_jscalendar", "/index.php?option=com_jscalendar&view=jscalendar&task=details&ev_id=1", ""],
    ["com_timetrack", "/index.php?option=com_timetrack&view=timetrack&ct_id=1", ""],
    ["com_biblioteca", "/index.php?option=com_biblioteca&view=biblioteca&testo=1", ""],
    ["com_amblog", "/index.php?option=com_amblog&task=article&articleid=1", ""],
    ["com_yellowpages", "/index.php?option=com_yellowpages&cat=1", ""],
    ["com_simpleshop", "/index.php?option=com_simpleshop&Itemid=26&task=viewprod&id=-999.1", ""],
    ["com_ttvideo", "/index.php?option=com_ttvideo&task=video&cid=1", ""],
    ["com_listbingo", "/index.php?option=com_listbingo&q=11111&catid=0&search_from_price=1", ""],
    ["com_answers", "/index.php?option=com_answers&task=detail&id=-1", ""],
    ["com_event", "/index.php?option=com_event&task=details&sid=1", ""],
    ["com_jdrugstopics", "/index.php?option=com_jdrugstopics&view=drugsdetails&id=1", ""],
    ["com_joomloc", "/index.php?option=com_joomloc&controller=loc&view=loc&layout=loc&task=edit&cid[]=1&id=1", ""],
    ["com_bookjoomlas", "/index.php?option=com_bookjoomlas&Itemid=26&func=comment&gbid=1", ""],
    ["com_equotes", "/index.php?option=com_equotes&id=1", ""],
    ["com_flashmagazinedeluxe", "/index.php?option=com_flashmagazinedeluxe&Itemid=10&task=magazine&mag_id=1", ""],
    ["com_news", "/index.php?option=com_news&id=1", ""],
    ["com_catalogproduction", "/index.php?option=com_catalogproduction&task=viewdetail&id=1", ""],
    ["com_dtregister", "/index.php?option=com_dtregister&eventId=1", ""],
    ["com_brightweblinks", "/index.php?option=com_brightweblinks&Itemid=58&catid=1", ""],
    ["com_versioning", "/index.php?option=com_versioning&task=edit&id=1", ""],
    ["com_jabode", "/index.php?option=com_jabode&task=sign&sign=taurus&id=1", ""],
    ["com_netinvoice", "/index.php?option=com_netinvoice&action=orders&task=order&cid=1", ""],
    ["com_expshop", "/index.php?option=com_expshop&page=show_payment&catid=1", ""],
    ["com_simpleshop", "/index.php?option=com_simpleshop&task=browse&Itemid=29&catid=1", ""],
    ["com_rapidrecipe", "/index.php?option=com_rapidrecipe&page=viewrecipe&recipe_id=1", ""],
    ["com_gameq", "/index.php?option=com_gameq&task=page&category_id=1", ""],
    ["com_joomladate", "/index.php?option=com_joomladate&task=viewProfile&user=1", ""],
    ["com_departments", "/index.php?option=com_departments&id=1", ""],
    ["com_business", "/index.php?option=com_business&view=business�ion=37&category_id=1", ""],
    ["com_radio", "/index.php?option=com_radio&task=exibi_descricao&id=1", ""],
    ["com_television", "/index.php?option=com_television&view=television&id=1", ""],
    ["com_include", "/index.php?option=com_include&lang=en_GB&Itemid=50&ID_NLE=1", ""],
    ["com_bidding", "/index.php?option=com_bidding&id=1", ""],
    ["com_nfnaddressbook", "/index.php?option=com_nfnaddressbook&Itemid=61&action=viewrecord&record_id=1", ""],
    ["com_leader", "/index.php?option=com_leader&Itemid=3160&task=view&id=1", ""],
    ["com_about", "/index.php?option=com_about&task=view&id=1", ""],
    ["com_products", "/index.php?option=com_products&intCategoryId=1", ""],
    ["com_yanc", "/index.php?option=com_yanc&Itemid=75&listid=1", ""],
    ["com_hdvideoshare", "/index.php?option=com_hdvideoshare&view=player&id=1", ""],
    ["com_videos", "/index.php?option=com_videos&act=view&Itemid=27&id=1", ""],
    ["com_productbook", "/index.php?option=com_productbook&Itemid=97&func=detail&id=1", ""],
    ["com_book", "/index.php?option=com_book&controller=listtour&task=showTour&cid[]=1", ""],
	// Ovidiu 1may2013
	["com_xball", "/index.php?option=com_xball&controller=teams&task=show&team_id=1", ""],
	["com_br", "/index.php?option=com_br&controller=../../../../../../../../../../../../../etc/passwd%00", ""],
	["com_simpledownload", "/index.php?option=com_simpledownload&controller=../../../../../../../../../../../../../../../proc/self/environ%00", ""],
	["com_kp", "/index.php?option=com_kp&controller=1", ""],
	["com_bulkenquery", "/index.php?option=com_bulkenquery&controller=../../../../../../../../../../../../../etc/passwd%00", ""],
	["com_boss", "/index.php?option=com_boss&controller=../../../../../../../../../../../../../etc/passwd%00", ""],
	["com_mobile", "/index.php?option=com_mobile&view=mobile&layout=songsdownload&id=1", ""],
	["com_mobile", "/index.php?option=com_mobile&format=raw&task=rezome&idshop=1", ""],
	["com_jesubmit", "/index.php?option=com_jesubmit&view=jesubmit&Itemid=[id]&lang=en", ""],
	["com_advert", "/index.php?option=com_advert&id=1", ""],
	["com_products", "/index.php?option=com_products&task=category&catid=1", ""],
	["com_products", "/index.php?option=com_products&id=1", ""],
	["com_products", "/index.php?option=com_products&catid=1", ""],
	["com_products", "/index.php?option=com_products&product_id=1", ""],
	["com_products", "/index.php?option=com_products&task=detail&parent_id=1", ""],
	["com_products", "/index.php?option=com_products&task=edit_productdetail&id_pro=1", ""],
	["com_products", "/index.php?option=com_products&Itemid=53&controller=home&task=displayitem&itemcode=1", ""],
	["com_products", "/index.php?option=com_products&catid=1&Cat[]=1", ""],
	["com_products", "/index.php?option=com_products&cid=1", ""],
	["com_products", "/index.php?option=com_products&view=products&id=19&cat=1", ""],
	["com_products", "/index.php?option=com_products&task=product&pid=1", ""],
	["com_products", "/index.php?option=com_products&Itemid=1", ""],
	["com_propertylab", "/index.php?option=com_propertylab&task=showproperty&id=1", ""],
	["com_bbs", "/index.php?option=com_bbs&bid=1", ""],
	["com_bbs", "/index.php?option=com_bbs&task=list&bid=1", ""],
	["com_bbs", "/index.php?option=com_bbs&Itemid=xxx&task=search&search_type=1", ""],
	["com_firmy", "/index.php?option=com_firmy&task=section_show_set&Id=1", ""],
	["com_visa", "/index.php?option=com_visa&controller=../../../../../../../../../../../../../etc/passwd%00", ""],
	["com_visa", "/index.php?option=com_visa&view=book&id=1", ""],
	["com_visa", "/index.php?option=com_visa&Itemid=35&page=1", ""],
	["com_bnf", "/index.php?option=com_bnf&task=listar&action=filter_add&seccion=pago&seccion_id=1&direccion=&direct=0&Itemid=0&lang=es", ""],
	["com_xcomp", "/index.php?option=com_xcomp&controller=1", ""],
	["com_x-shop", "/index.php?option=com_x-shop&action=artdetail&idd=1", ""],
	["com_xvs", "/index.php?option=com_xvs&controller=1", ""],
	["com_machine", "/index.php?option=com_machine&view=machine&Itemid=1", ""],
	["com_machine", "/index.php?option=com_machine&view=machine&Itemid=xxx&idMacchina=1", ""],
	["com_dtregister", "/index.php?option=com_dtregister&task=category&list1=1", ""],
	["com_estateagent", "/index.php?option=com_estateagent&Itemid=47&act=object&task=showEO&id=1", ""],
	["com_bearleague", "/index.php?option=com_bearleague&task=team&tid=8&sid=1&Itemid=1", ""],
	["com_ponygallery", "/index.php?option=com_ponygallery&Itemid=1", ""],
	["com_videogallery", "/index.php?option=com_videogallery&Itemid=1", ""],
	["com_alphacontent", "/index.php?option=com_alphacontent&section=weblinks&Itemid=1&lang=de&limitstart=1", ""],
	["com_contushdvideoshare", "/index.php?option=com_contushdvideoshare&view=player&id=1", ""],
	// Ovidiu 2may2013
	["com_ksadvertiser", "/index.php?option=com_ksadvertiser&Itemid=36&task=add&catid=0&lang=en", ""],
	["com_hello", "/index.php?option=com_hello&controller=../../../../../../../../etc/passwd%00", ""],
	["com_odudeprofile", "/index.php?option=com_odudeprofile&view=search&profession=1", ""],
	["com_movm", "/index.php?option=com_movm&controller=product&task=product&id=1", ""],
	["com_niceajaxpoll", "/index.php?option=com_niceajaxpoll&getpliseid=1", ""],
	["com_photo", "/index.php?option=com_photo&task=gallery&AlbumId=1", ""],
	["com_package", "/index.php?option=com_package&task=details&id=1", ""],
	["com_enmasse", "/index.php?categoryId=1&controller=deal&keyword=1&locationId=1&option=com_enmasse&sortBy=1", ""],
	["com_fireboard", "/index.php?option=com_fireboard&Itemid=0&id=1&catid=0&func=fb_pdf", ""],
	["com_rokmodule", "/index.php?option=com_rokmodule&tmpl=component&type=raw&module=1", ""],
	["com_rokmodule", "/web/index.php?option=com_rokmodule&tmpl=component&type=raw&module=1", ""],
	["com_icagenda", "/index.php?option=com_icagenda&view=list&layout=event&Itemid=520&id=1", ""],
	["com_icagenda", "/index.php?option=com_icagenda&view=list&layout=event&Itemid=520&id[]=1", ""],
	["com_fss", "/index.php?option=com_fss&view=test&prodid=1", ""],
	["com_szallasok", "/index.php?option=com_szallasok&mode=8&id=1", ""],
	// Ovidiu 3may2013
	["com_spidercatalog", "/index.php?option=com_spidercatalog&product_id=1", ""],
	["com_jooproperty", "/?option=com_jooproperty&view=booking&layout=modal&product_id=1", ""],
	["com_biblioteca", "/components/com_biblioteca/views/biblioteca/tmpl/pdf.php?pag=1&testo=1", ""],
	["com_biblioteca", "/components/com_biblioteca/views/biblioteca/tmpl/stampa.php?pag=1&testo=1", ""],
	["com_cgtestimonial", "/components/com_cgtestimonial/video.php?url=1", ""],
	["com_extcalendar", "/components/com_extcalendar/cal_popup.php?extmode=view&extid=1", ""],
	["com_hwdvideoshare", "/components/com_hwdvideoshare/assets/uploads/flash/flash_upload.php?jqUploader=1", ""],
	["com_aardvertiser", "/index.php?option=com_aardvertiser&cat_name=1&task=view", ""],
	["com_aardvertiser", "/index.php?option=com_aardvertiser&cat_name=conf&task=1", ""],
	["com_aardvertiser", "/index.php?option=com_aardvertiser&task=1", ""],
	["com_abc", "/index.php?option=com_abc&view=abc&letter=AS&sectionid=1", ""],
	["com_alameda", "/index.php?option=com_alameda&controller=comments&task=edit&storeid=1", ""],
	["com_alfurqan15x", "/index.php?option=com_alfurqan15x&action=viewayat&surano=1", ""],
	["com_amblog", "/index.php?option=com_amblog&view=amblog&catid=1", ""],
	["com_annonces", "/index.php?option=com_annonces&view=edit&Itemid=1", ""],
	["com_beeheard", "/index.php?option=com_beeheard&controller=../../../../../../../../../../etc/passwd%00", ""],
	["com_blogfactory", "/index.php?option=com_blogfactory&controller=../../../../../../../../../../etc/passwd%00", ""],
	["com_chronoconnectivity", "/index.php?option=com_chronoconnectivity&itemid=1", ""],
	["com_chronocontact", "/index.php?option=com_chronocontact&itemid=1", ""],
	["com_clantools", "/index.php?option=com_clantools&squad=1", ""],
	["com_clantools", "/index.php?option=com_clantools&task=clanwar&showgame=1", ""],
	["com_commedia", "/index.php?option=com_commedia&format=raw&task=image&pid=4&id=1", ""],
	["com_commedia", "/index.php?option=com_commedia&task=page&commpid=1", ""],
	["com_connect", "/index.php?option=com_connect&view=connect&controller=1", ""],
	["com_delicious", "/index.php?option=com_delicious&controller=../../../../../../../../../../etc/passwd%00", ""],
	["com_dioneformwizard", "/index.php?option=com_dioneformwizard&controller=1", ""],
	["com_dshop", "/index.php?option=com_dshop&controller=fpage&task=flypage&idofitem=12", ""],
	["com_easyfaq", "/index.php?option=com_easyfaq&Itemid=1&task=view&gid=1", ""],
	["com_easyfaq", "/index.php?option=com_easyfaq&task=view&contact_id=1", ""],
	["com_elite_experts", "/index.php?option=com_elite_experts&task=showExpertProfileDetailed&getExpertsFromCountry=&language=ru&id=1", ""],
	["com_equipment", "/index.php?option=com_equipment&task=components&id=45&sec_men_id=1", ""],
	["com_equipment", "/index.php?option=com_equipment&view=details&id=1", ""],
	["com_etree", "/index.php?option=com_etree&view=displays&layout=category&id=1", ""],
	["com_etree", "/index.php?option=com_etree&view=displays&layout=user&user_id=1", ""],
	["com_ezautos", "/index.php?option=com_ezautos&Itemid=49&id=1&task=helpers&firstCode=1", ""],
	["com_fabrik", "/index.php?option=com_fabrik&view=table&tableid=1", ""],
	["com_filecabinet", "/index.php?option=com_filecabinet&task=download&cid[]=1", ""],
	["com_golfcourseguide", "/index.php?option=com_golfcourseguide&view=golfcourses&cid=1&id=1", ""],
	["com_graphics", "/index.php?option=com_graphics&controller=1", ""],
	["com_grid", "/index.php?option=com_grid&gid=1&data_search=1", ""],
	["com_huruhelpdesk", "/index.php?option=com_huruhelpdesk&view=detail&cid[0]=1", ""],
	["com_iproperty", "/index.php?option=com_iproperty&view=agentproperties&id=1", ""],
	["com_jacomment", "/index.php?option=com_jacomment&view=../../../../../../../../../../etc/passwd%00", ""],
	["com_javoice", "/index.php?option=com_javoice&view=../../../../../../../../../../../../../../../etc/passwd%00", ""],
	["com_jcommunity", "/index.php?option=com_jcommunity&controller=members&task=1", ""],
	["com_jeajaxeventcalendar", "/index.php?option=com_jeajaxeventcalendar&view=alleventlist_more&event_id=1", ""],
	["com_jefaqpro", "/index.php?option=com_jefaqpro&view=category&layout=categorylist&catid=1", ""],
	["com_jefaqpro", "/index.php?option=com_jefaqpro&view=category&layout=categorylist&task=lists&catid=1", ""],
	["com_jeguestbook", "/index.php?option=com_jeguestbook&view=../../../../../../../../etc/passwd%00", ""],
	["com_jeguestbook", "/index.php?option=com_jeguestbook&view=item_detail&d_itemid=1", ""],
	["com_jfuploader", "/index.php?option=com_jfuploader&Itemid=1", ""],
	["com_jgen", "/index.php?option=com_jgen&task=view&id=1", ""],
	["com_jgrid", "/index.php?option=com_jgrid&controller=../../../../../../../../etc/passwd%00", ""],
	["com_jimtawl", "/index.php?option=com_jimtawl&Itemid=12&task=1", ""],
	["com_jmarket", "/index.php?option=com_jmarket&controller=product&task=1", ""],
	["com_jobprofile", "/index.php?option=com_jobprofile&Itemid=61&task=profilesview&id=1", ""],
	["com_jomdirectory", "/index.php?option=com_jomdirectory&task=search&type=1", ""],
	["com_joomdle", "/index.php?option=com_joomdle&view=detail&cat_id=1&course_id=1", ""],
	["com_joomla_flash_uploader", "/index.php?option=com_joomla_flash_uploader&Itemid=1", ""],
	["com_joomleague", "/index.php?option=com_joomleague&func=showNextMatch&p=1", ""],
	["com_joomleague", "/index.php?option=com_joomleague&view=resultsmatrix&p=4&Itemid=1", ""],
	["com_joomtouch", "/index.php?option=com_joomtouch&controller=1", ""],
	["com_jphone", "/index.php?option=com_jphone&controller=../../../../../../../../../../proc/self/environ%00", ""],
	["com_jstore", "/index.php?option=com_jstore&controller=product-display&task=1", ""],
	["com_jstore", "/index.php?option=com_jstore&controller=1", ""],
	["com_jsubscription", "/index.php?option=com_jsubscription&controller=subscription&task=1", ""],
	["com_jtickets", "/index.php?option=com_jtickets&controller=ticket&task=1", ""],
	["com_konsultasi", "/index.php?option=com_konsultasi&act=detail&sid=1", ""],
	["com_lead", "/index.php?option=com_lead&task=display&archive=1&Itemid=65&leadstatus=1", ""],
	["com_lovefactory", "/index.php?option=com_lovefactory&controller=../../../../../../../../../../etc/passwd%00", ""],
	["com_markt", "/index.php?option=com_markt&page=show_category&catid=1", ""],
	["com_matamko", "/index.php?option=com_matamko&controller=1", ""],
	["com_newsfeeds", "/index.php?option=com_newsfeeds&view=categories&feedid=1", ""],
	["com_noticeboard", "/index.php?option=com_noticeboard&controller=1", ""],
	["com_obsuggest", "/index.php?option=com_obsuggest&controller=1", ""],
	["com_ongallery", "/index.php?option=com_ongallery&task=ft&id=1", ""],
	["com_oziogallery", "/index.php?option=com_oziogallery&Itemid=1", ""],
	["com_kunena", "/index.php?option=com_kunena&func=userlist&search=1", ""],
	// Ovidiu 6th may 2013 - 17th july 2014
	["com_pcchess", "/index.php?option=com_pcchess&controller=../../../../../../../../../../../../../etc/passwd%00", ""],
	["com_peliculas", "/index.php?option=com_peliculas&view=peliculas&id=1", ""],
	["com_phocagallery", "/index.php?option=com_phocagallery&view=categories&Itemid=1", ""],
	["com_photomapgallery", "/index.php?option=com_photomapgallery&view=imagehandler&folder=1", ""],
	["com_php", "/index.php?option=com_php&file=../../../../../../../../../../etc/passwd", ""],
	["com_qcontacts", "/index.php?option=com_qcontacts&Itemid=1", ""],
	["com_qcontacts", "/index.php?option=com_qcontacts?=catid=0&filter_order=1&filter_order_Dir=&option=com_qcontacts", ""],
	["com_record", "/index.php?option=com_record&controller=../../../../../../../../../../etc/passwd%00", ""],
	["com_restaurantguide", "/index.php?option=com_restaurantguide&view=country&id=1&Itemid=69", ""],
	["com_seyret", "/index.php?option=com_seyret&view=1", ""],
	["com_smartsite", "/index.php?option=com_smartsite&controller=1", ""],
	["com_spa", "/index.php?option=com_spa&view=spa_product&cid=1", ""],
	["com_spielothek", "/index.php?option=com_spielothek&task=savebattle&bid=1", ""],
	["com_spielothek", "/index.php?option=com_spielothek&view=battle&wtbattle=ddbdelete&dbtable=vS&loeschen[0]=1", ""],
	["com_spielothek", "/index.php?option=com_spielothek&view=battle&wtbattle=play&bid=1", ""],
	["com_timereturns", "/index.php?option=com_timereturns&view=timereturns&id=1", ""],
	["com_ultimateportfolio", "/index.php?option=com_ultimateportfolio&controller=1", ""],
	["com_virtuemart", "/index.php?option=com_virtuemart&page=account.index&keyword=1", ""],
	["com_worldrates", "/index.php?option=com_worldrates&controller=../../../../../../../../../../etc/passwd%00", ""],
	["com_yjcontactus", "/index.php?option=com_yjcontactus&view=1", ""],
	["com_youtube", "/index.php?option=com_youtube&id_cate=4", ""],
	["com_zina", "/index.php?option=com_zina&view=zina&Itemid=9", ""],
	["com_zoomportfolio", "/index.php?option=com_zoomportfolio&view=portfolio&view=portfolio&id=1", ""],
	["com_esearch", "/index.php?search=NoGe&option=com_esearch&searchId=1", ""],
	["com_socialads", "/js/index.php?option=com_socialads&view=showad&Itemid=94", ""],
	["com_s5clanroster", "/index.php?option=com_s5clanroster&view=s5clanroster&layout=category&task=category&id=1", ""],
	["com_shohada", "/index.php?option=com_shohada&controller=../../../../../../../../../../etc/passwd%00", ""],
	["com_phocagallery", "/components/com_phocagallery/assets/plupload/plupload.flash.swf?id=1", ""],
	["com_jnews", "/components/com_jnews/includes/openflashchart/open-flash-chart.swf?get-data=1", ""],
	["core", "/modules/mod_ccnewsletter/helper/popup.php?id=1", ""],
	["core", "/modules/mod_visitorsgooglemap/map_data.php?action=listpoints&lastMarkerID=0", ""],
	["{admin}com_abcalendar", "/administrator/components/com_abcalendar/load-calendar.php?view=3&month=7&year=2063&cid=1", ""],
	["mod_xoranalogclock", "/media/xorAnalogClock.swf#?urlWindow=_self&widgetUrl=1", ""],
	["com_newssearch", "/index.php?option=com_newssearch&type=list&section=1&cid=1", ""],
	["com_expose", "/components/com_expose/showpic.html?img=&caption=1", ""],
	["com_easybookreloaded", "/index.php?option=com_easybookreloaded&view=easybookreloaded&Itemid=1", ""],
	["com_collector", "/index.php?option=com_collector&view=filelist&tmpl=component&folder=&type=1", ""],
	["com_sectionex", "/index.php?option=com_sectionex&view=category&id=X&Itemid=Y", "filter_title=&filter_content=&limit=0&sectionid=20&filter_order=1&filter_order_Dir=1"],
	["com_redshop", "/index.php?tmpl=component&option=com_redshop&view=product&task=addtocompare&pid=1&cmd=add&cid=20&sid=0.6886686905513422", ""],
	["com_sexypolling", "/components/com_sexypolling/vote.php", "answer_id[]=1"],
	["com_jvcomment", "/index.php", "option=com_jvcomment&task=comment.like&id=1"],
	["com_komento", "/?option=com_komento", "tmpl=component&format=ajax&no_html=1&component=com_content&cid=24&comment=comment&parent_id=0&name=name&email=1&website=1&subscribe=false&latitude=1&longitude=1&address=1&contentLink=1&pageItemId=435&option=com_komento&namespace=site.views.komento.addcomment&4873559e1d03545682ae270bf7b0c8ec=1"],
	["com_wire_immogest", "/index.php?option=com_wire_immogest&view=object&id=1", ""],
	["com_melody", "/components/com_melody/assets/swfupload/swfupload.swf?buttonText=1", ""],
	["com_multicalendar", "/index.php?option=com_multicalendar&task=editevent&calid=1", ""],
	["com_multicalendar", "/index.php?option=com_multicalendar&task=editevent&paletteDefault=1", ""],
	["{admin}com_pbbooking", "/administrator/index.php?option=com_pbbooking&controller=manage&task=edit", "id=1&date=1&xss=1&submit2=Submit"],
	["com_youtubegallery", "/components/com_youtubegallery/includes/flvthumbnail.php?videofile=1", ""],
	["com_phocaguestbook", "/index.php?option=com_phocaguestbook&view=phocaguestbook&id=1&Itemid=1", ""],
	["com_youtubegallery", "/index.php?option=com_youtubegallery&view=youtubegallery&listid=1&themeid=1&videoid=ETMVUuFbToQ&tmpl=component&TB_iframe=true&height=500&width=700", ""],
	["com_pbbooking", "/index.php?option=com_pbbooking&task=validate&id=1", ""],
	// Ovidiu 19th january 2016 - 20th january 2016
	["com_cbe", "/index.php?option=com_cbe&task=userProfile&user=23&ajaxdirekt=true&tabname=1", ""],
	["com_preachit", "/components/com_preachit/assets/swfupload/swfupload.swf?buttonText=1", ""],
	["com_wordpress", "/components/com_wordpress/wp/wp-includes/js/swfupload/swfupload.swf?buttonText=1", ""],
	["com_rsfiles", "/index.php?option=com_rsfiles&view=files&layout=agreement&tmpl=component&cid=1", ""],
	["com_docmanpaypal", "/index.php?option=com_docmanpaypal&task=file&id=1", ""],
	["{admin}com_civicrm", "/administrator/components/com_civicrm/civicrm/packages/OpenFlashChart/php-ofc-library/ofc_upload_image.php?name=", ""],
	["com_jvideoclip", "/index.php?option=com_jvideoclip&view=search&type=user&uid=1&Itemid=6", ""],
	["com_mijosearch", "/component/mijosearch/search?query=1&limit=15&order=relevance&orderdir=desc", ""],
	["com_acesearch", "/index.php/component/acesearch/search?query=1", ""],
	["com_spidervideoplayer", "/component/spidervideoplayer/?view=settings&format=row&typeselect=0&playlist=1,&theme=1", ""],
	["com_virtuemart", "/index.php?option=com_virtuemart&view=user&task=removeAddressST&virtuemart_userinfo_id=1", ""]
        
);
var plugins = new Array();
var lastJob = null;
// **************************************************************************************							 
function alert(uri, vxml, job, matchedText)
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
function test_joomla_1_6_0_sql_injection(dir, uri)
{
	//trace(uri);
	lastJob = new THTTPJob();
	lastJob.verb = "GET";
	lastJob.url  = dir.url;
	lastJob.uri  = uri + '/index.php/extensions/components/content-component/article-category-list/?filter_order=acunetix_wvs,&filter_order_Dir=2&limit=3&limitstart=4';		
	
	lastJob.execute();
	
	//trace(lastJob.responseStatus);
	
	if (!lastJob.wasError && !lastJob.notFound) 
	{
		if (lastJob.responseStatus == 500 && lastJob.response.body.indexOf('Unknown column \'acunetix_wvs\' in \'order clause\' SQL=SELECT a.id, a.title, a.alias, a.title_alias, a.introtext, a.catid, a.created, a.created_by, a.created_by_alias') != -1)
		{
				// successful
				alert(uri, 'joomla_1_6_0_sql_injection.xml', lastJob);
				return true;				
		}
	}		
	
	return false;
}
/***********************************************************************************/
function test_joomla_priv_escalation_and_sql_injection(dir, uri)
{
	//trace(uri);
    // check 1.6.x and 1.7.x for priv esc
	lastJob = new THTTPJob();
	lastJob.verb = "GET";
	lastJob.url  = dir.url;
	lastJob.uri  = uri + '/README.txt';		
	
	lastJob.execute();
	
	//trace(lastJob.responseStatus);
	
	var reportedPrivEscAlert = false;
	
	if (!lastJob.wasError && !lastJob.notFound) 
	{
		if (lastJob.responseStatus == 200 && (lastJob.response.body.indexOf('This is a Joomla! installation/upgrade package to version 1.6.x') != -1 || lastJob.response.body.indexOf('This is a Joomla! installation/upgrade package to version 1.7.x') != -1))
		{
				// successful
				alert(uri, 'joomla_16_17_25_Privilege_Escalation.xml', lastJob);	
                reportedPrivEscAlert = true;			
		}
	}		
    
    // try to determine the joomla version
	lastJob = new THTTPJob();
	lastJob.verb = "GET";
	lastJob.url  = dir.url;
	lastJob.uri  = uri + '/administrator/manifests/files/joomla.xml';		
	
	lastJob.execute();
	
	//trace(lastJob.responseStatus);
	
	if (!lastJob.wasError && !lastJob.notFound) 
	{
        // look for priv_esc
		if (lastJob.responseStatus == 200 && 
                (
                lastJob.response.body.indexOf('<version>2.5.0</version>') != -1 
                || lastJob.response.body.indexOf('<version>2.5.1</version>') != -1
                || lastJob.response.body.indexOf('<version>2.5.2</version>') != -1
                )
           )
		{
                if (!reportedPrivEscAlert) 
                    alert(uri, 'joomla_16_17_25_Privilege_Escalation.xml', lastJob);
    	}
        
        // look for sql injection
		if (lastJob.responseStatus == 200 && 
                (
                lastJob.response.body.indexOf('<version>2.5.0</version>') != -1 
                || lastJob.response.body.indexOf('<version>2.5.1</version>') != -1
                || lastJob.response.body.indexOf('<version>1.7.0</version>') != -1
                || lastJob.response.body.indexOf('<version>1.7.1</version>') != -1
                || lastJob.response.body.indexOf('<version>1.7.2</version>') != -1
                || lastJob.response.body.indexOf('<version>1.7.3</version>') != -1
                || lastJob.response.body.indexOf('<version>1.7.4</version>') != -1
                )
           )
		{
                alert(uri, 'joomla_25_17_Core_SQL_Injection.xml', lastJob);                
		}        
	}		
	return false;
}
// **************************************************************************************
function pluginIsInstalled(dir, uri){
    // core
    if(uri.endsWith("/core")) 
        return true;
    
    var res = false;
	lastJob = new THTTPJob();
	lastJob.verb = "GET";
	lastJob.url  = dir.url;
    lastJob.uri  = uri;
    
	lastJob.execute();
    
    if (!lastJob.wasError) {
        if (lastJob.responseStatus == 301 || lastJob.responseStatus == 302)
            {
                var locationStr = lastJob.response.headerValue('location');
    			if (locationStr && locationStr.indexOf(uri + "/") != -1)  
                    res = true;                
            }            
    }    
	return res;     
}
// **************************************************************************************
function detectInstalledPlugins(dir, root_path) {
    // get list of plugins
    for (var i=0; i<files.length; i++)
    	if (files[i][0]) plugins.push(files[i][0]);
    // remove duplicates
    plugins = eliminateDuplicates(plugins);
    
    // look for false positives
    var plugin_dir = root_path + "/components/" + randStr(8);
    var bogusDir = false;
    if (pluginIsInstalled(dir, plugin_dir)) {
        bogusDir = true;
    }
    
    if (!bogusDir) {
        for (var i=0; i<plugins.length; i++){
            
            var plugin_name = plugins[i];
            var plugin_dir = root_path + "/components/" + plugin_name;
            
            // administator plugin?
            if (plugin_name.startsWith("{admin}")) {
                plugin_name = plugin_name.replace("{admin}", "");
                plugin_dir = root_path + "/administrator/components/" + plugin_name;
            }
                        
            if (pluginIsInstalled(dir, plugin_dir)) {
                trace("plugin installed " + plugin_name);
                
                // add http requests to the crawler
                for (var j=0; j<files.length; j++)
                	if (files[j][0] == plugin_name) {
                        var getData = files[j][1];
                        var postData = files[j][2];
                        
                        // add request
                        var r = new THTTPRequest();
                        var dir = getCurrentDirectory();
                        
                        r.URI = root_path + getData;                        
                        
                        if (postData) {                            
                            r.Verb = 'POST';
                            r.body = postData;
                            r.addHeader('Content-Type', 'application/x-www-form-urlencoded', true);
                        } 
                        else r.Verb = 'GET';
                        
                        addHTTPRequestToCrawler(r);                              
                }                
            }           
        }
    }
}
// **************************************************************************************
function testForVulnPlugins(dir) {
    root_path = dir.fullPath;
    detectInstalledPlugins(dir, root_path);
}