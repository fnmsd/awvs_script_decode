function getCrawlerResponseForSchemeVariation (scheme) {
	var result = null;
	if (engineVersion >= 0x301) {
		var schemeTarget = getSiteFileWithPath(scheme.path, 2);
		if (schemeTarget) {
			var fileVariation = schemeTarget.getVariation(scheme.variationHash);
			if (fileVariation) {
				result = fileVariation.response;
			}
		}
	}
	
	return result;
}
