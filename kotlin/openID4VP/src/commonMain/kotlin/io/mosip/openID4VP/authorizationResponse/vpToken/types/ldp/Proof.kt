package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import kotlinx.serialization.Serializable

@Serializable
class Proof(
    val type: String,
    val created: String? = null,
    val challenge: String,
    val domain: String,
    var proofValue: String? = null,
    var jws: String? = null,
    val proofPurpose: String? = null,
    var verificationMethod: String,
    var signatureValue: String? = null,
    val cryptosuite: String? = null
)
