package io.mosip.openID4VP.common

import com.danubetech.dataintegrity.canonicalizer.RDFC10SHA256Canonicalizer
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import foundation.identity.jsonld.JsonLDObject
import java.security.MessageDigest

object RDFC10Canonicalization {
    /**
     * Produces the hash data defined by the RDFC Data Integrity cryptosuites:
     * SHA-256(canonical proof configuration) || SHA-256(canonical unsecured document).
     */
    fun canonicalizeDataIntegrity(jsonString: String): ByteArray {
        val mapper = jacksonObjectMapper()
        val document = mapper.readValue(
            jsonString,
            object : TypeReference<MutableMap<String, Any>>() {}
        )
        val proofValue = document.remove("proof")
        if (proofValue is List<*>) {
            throw IllegalArgumentException("Multiple Data Integrity proofs are not supported")
        }
        val proof = (proofValue as? Map<*, *>)
            ?.entries
            ?.associate { it.key.toString() to it.value as Any }
            ?.toMutableMap()
            ?: throw IllegalArgumentException("Data Integrity proof configuration is missing")

        proof.remove("proofValue")
        proof["@context"] = requireNotNull(document["@context"]) {
            "Data Integrity document @context is missing"
        }

        val documentLoader = JsonLDProcessor.getDocumentLoader()
        val unsecuredDocument = JsonLDObject.fromJson(mapper.writeValueAsString(document)).also {
            it.documentLoader = documentLoader
        }
        val proofConfiguration = JsonLDObject.fromJson(mapper.writeValueAsString(proof)).also {
            it.documentLoader = documentLoader
        }

        val canonicalizer = RDFC10SHA256Canonicalizer.getInstance()
        val canonicalProof = canonicalizer.canonicalize(proofConfiguration).toByteArray(Charsets.UTF_8)
        val canonicalDocument = canonicalizer.canonicalize(unsecuredDocument).toByteArray(Charsets.UTF_8)
        val sha256 = MessageDigest.getInstance("SHA-256")
        return sha256.digest(canonicalProof) + sha256.digest(canonicalDocument)
    }
}
