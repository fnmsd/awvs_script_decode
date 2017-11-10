function alertComposerVulnDep(details, path, job)
{
    var ri = new TReportItem();
    ri.LoadFromFile('Composer_Lock_Vulnerable_Dependencies.xml');
    ri.affects = path;
    ri.alertPath = "Scripts/" + ri.Name;
    ri.setHttpInfo(job);
    if (details)
        ri.Details =  details;
    AddReportItem(ri);
}
// check if a package is on the list of vulnerable packages and returns info about it if so
// if not vulnerable returns false
function vulnPackage(pkgName, pkgVersion) {
    var vulnerabilities = [];
    for (var i = 0; i < composerVulns.length; i++) {
        vuln = composerVulns[i];
        vulnName = vuln.reference.replace("composer://", "");
        if (vulnName == pkgName) {
            //if (debug) trace(vulnName);
            var vulnerable = false;
            for (branch in vuln.branches) {
                //if (debug) trace("   " + branch);
                var versions = vuln.branches[branch].versions;
                var hits = 0;
                for (var j = 0; j < versions.length; j++) {
                    if (versions[j]) {
                        //if (debug) trace("     " + versions[j]);
                        var match = versions[j].match("^([<>=]+)")
                        if (match && match[1]) {
                            var operator = match[1];
                            var version = versions[j].slice(operator.length);
                            if (version_compare(pkgVersion, version, operator)) {
                                hits = hits + 1;
                            }
                        }
                    }
                }
                if (hits > 0 && hits==versions.length) vulnerable = true;
            }
            if (vulnerable) {
                vulnTitle = vuln.title;
                vulnLink  = vuln.link;
                if (vuln.cve) vulnCVE = vuln.cve;
                else vulnCVE = "N/A";
                if (debug) trace("vulnerable " + pkgName + " => " + vulnTitle);
                vulnerabilities.push({"package":pkgName, "version":pkgVersion, "title": vulnTitle, "link": vulnLink, "cve": vulnCVE});
            }
        }
    }
    return vulnerabilities;
}
// audit composer.lock files looking for known vulnerable packages.
function auditComposerLockFile(path, body, job) {
    if (debug) trace("auditing " + path);
    if (debug) trace("parse response body ...");
    var packages = [];
    var obj = JSON.parse(body);
    if (debug) trace(obj.packages.length + " packages used");
    var vulnerablePackages = [];
    for (var i = 0; i < obj.packages.length; i++) {
        pkg = obj.packages[i];
        pkgName = pkg.name;
        pkgDescr = pkg.description;
        pkgHomepage = pkg.homepage;
        pkgVersion = pkg.version;
        packages.push({"name":pkgName, "version":pkgVersion, "description": pkgDescr, "homepage": pkgHomepage});
        // some version strings start with v (like v1.2.3) and some don't
        if (pkgVersion.startsWith("v"))
            pkgVersion = pkgVersion.slice(1);
        // the version should start with a number
        if (pkgVersion && /^\d/.test(pkgVersion))
        {
            vulns = vulnPackage(pkgName, pkgVersion);
            if (vulns.length > 0) {
                if (debug) trace(" [+] " + pkgName + " " + pkgVersion);
                for (var k = 0; k < vulns.length; k++) {
                    vulnerablePackages.push(vulns[k]);
                }
            }
        }
    }
    if (vulnerablePackages.length>0) {
        var details = "[bold]" + vulnerablePackages.length + "[/bold] vulnerabilities were found. [break][break]";
        for (var i=0; i<vulnerablePackages.length; i++) {
            var v = vulnerablePackages[i];
            details = details + "Package name: [bold]" + v.package + "[/bold][break]";
            details = details + "Package version: [dark][bold]v" + v.version + "[/bold][/dark][break]";
            details = details + "Vulnerability: " + v.title + "[break]";
            details = details + "Link: " + v.link + "[break]";
            details = details + "CVE: " + v.cve + "[break]";
            details = details + "[break]";
        }
        alertComposerVulnDep(details, path, job);
    }
    if (packages.length>0) {
        var details = "Composer lock file: [bold]" + path + "[/bold].[break][bold]" + packages.length + "[/bold] project dependencies were found. [break][break]";
        for (var i=0; i<packages.length; i++) {
            var v = packages[i];
            details = details + "Package name: [bold]" + v.name + "[/bold][break]";
            details = details + "Package version: v" + v.version + "[break]";
            details = details + "Description: " + v.description + "[break]";
            details = details + "Homepage: " + v.homepage + "[break]";
            details = details + "[break]";
        }
        KBase("Composer.lock project dependencies", details);
    }
}
