package io.mosip.openID4VP.common

import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData

internal object W3cCredentialUtils {
    const val VCDM_V1_CONTEXT = "https://www.w3.org/2018/credentials/v1"
    const val VCDM_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"

    @Suppress("UNCHECKED_CAST")
    fun isVcdm2Credential(credential: Any, className: String): Boolean {
        val credentialMap = credential as? Map<String, Any>
            ?: throw InvalidData("Credential is not a valid JSON object", className)
        val contexts = credentialMap["@context"] as? List<*>
            ?: throw InvalidData("Credential @context must be an ordered array", className)
        val first = contexts.firstOrNull() as? String
            ?: throw InvalidData("Credential @context is missing", className)
        if (first == VCDM_V2_CONTEXT) return true
        if (first == VCDM_V1_CONTEXT) {
            if (contexts.drop(1).contains(VCDM_V2_CONTEXT)) {
                throw InvalidData("VC 2.0 context must be the first @context entry", className)
            }
            return false
        }
        throw InvalidData("Unsupported credential data model context: $first", className)
    }
}
