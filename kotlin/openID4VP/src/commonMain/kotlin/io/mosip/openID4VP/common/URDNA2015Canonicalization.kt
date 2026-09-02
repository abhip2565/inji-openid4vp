package io.mosip.openID4VP.common

import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer

object URDNA2015Canonicalization{
    fun canonicalize(jsonString: String): String{
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(jsonString)
        vcJsonLdObject.documentLoader = JsonLDProcessor.getDocumentLoader()
        val ldProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
        val canonicalizer = URDNA2015Canonicalizer()
        val canonicalHashBytes = canonicalizer.canonicalize(ldProof, vcJsonLdObject)
        return encodeToBase64Url(canonicalHashBytes)
    }
}
