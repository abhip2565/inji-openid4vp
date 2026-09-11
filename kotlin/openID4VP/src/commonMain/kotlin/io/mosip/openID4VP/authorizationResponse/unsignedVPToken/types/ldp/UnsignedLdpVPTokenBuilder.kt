package io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.getMatchingCredentialQuery
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.LdpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp.Proof
import io.mosip.openID4VP.common.URDNA2015Canonicalization
import io.mosip.openID4VP.common.RDFC10Canonicalization
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.common.W3cCredentialUtils.VCDM_V1_CONTEXT
import io.mosip.openID4VP.common.W3cCredentialUtils.VCDM_V2_CONTEXT
import io.mosip.openID4VP.common.W3cCredentialUtils.isVcdm2Credential
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToJsonString
import io.mosip.openID4VP.common.resolveJWSAlgorithm
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2018
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.Ed25519Signature2020
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.JsonWebSignature2020
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm.DataIntegrityProof
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.SUPPORTED_HOLDER_DID_PATTERN
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private const val LDP_INTERNAL_PATH = "verifiableCredential"
private const val className = "UnsignedLdpVPTokenBuilder"
private const val EDDSA_RDFC_2022 = "eddsa-rdfc-2022"
private const val ECDSA_RDFC_2019 = "ecdsa-rdfc-2019"

internal class UnsignedLdpVPTokenBuilder(
    override val authorizationRequest: AuthorizationRequest,
    override val specVersion: SpecVersion,
    private val id: String,
    override val walletConfig: WalletConfig
) : UnsignedVPTokenBuilder {

    @JvmName("buildForPex")
    fun build(credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>): Pair<Map<String, Any>, List<UnsignedVPToken>> {
        if (credentialInputDescriptorMappings.isEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "No credentials provided for LDP VP Token",
                className
            )
        }

        val vpTokenSigningPayloads = mutableMapOf<String, LdpVPToken>()
        val unsignedVPTokens = mutableListOf<UnsignedVPToken>()

        credentialInputDescriptorMappings.forEach { mapping ->
            val identifier = UUIDGenerator.generateUUID()
            mapping.identifier = identifier

            mapping.nestedPath = "$.$LDP_INTERNAL_PATH[0]"
            val (extractedHolder, extractedSuite) = extractHolderAndSignatureSuite(mapping.credential)
            val holder = validateHolderId(extractedHolder)
            val isVcdm2 = isVcdm2Credential(mapping.credential, className)

            val (vpPayload, unsignedTokens) = buildPayloadAndUnsignedVPToken(
                identifier,
                verifiableCredentials = listOf(mapping.credential),
                signatureSuite = extractedSuite,
                holder = holder,
                isVcdm2 = isVcdm2
            )
            val ldpVPToken = (vpPayload as? LdpVPToken
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Expected LdpVPToken as payload",
                    className
                ))
            vpTokenSigningPayloads[identifier] = ldpVPToken
            unsignedVPTokens.addAll(unsignedTokens)
        }

        return Pair(vpTokenSigningPayloads, unsignedVPTokens)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: MutableList<CredentialToCredentialQueryIdMapping>
    ): Pair<Map<String, Any>, List<UnsignedVPToken>> {
        val dcqlRequest = authorizationRequest as? AuthorizationDcqlRequest
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected AuthorizationDcqlRequest for DCQL flow", className
            )

        val unsignedVPTokens = mutableListOf<UnsignedVPToken>()
        val vpTokenSigningPayloads = mutableMapOf<String, Any>()

        credentialToCredentialQueryIdMappings.forEach { mapping ->
            val identifier = UUIDGenerator.generateUUID()
            mapping.identifier = identifier

            val credential = mapping.credential

            val matchedQuery =
                getMatchingCredentialQuery(dcqlRequest, mapping.credentialQueryId, className)

            if (!matchedQuery.requireCryptographicHolderBinding) {
                vpTokenSigningPayloads[identifier] = LdpVcToken(credential)
                return@forEach
            }

            val (extractedHolder, extractedSuite) = extractHolderAndSignatureSuite(credential)
            val holder = validateHolderId(extractedHolder)
            val isVcdm2 = isVcdm2Credential(credential, className)

            val (vpPayload, tokens) = buildPayloadAndUnsignedVPToken(
                identifier,
                verifiableCredentials = listOf(credential),
                signatureSuite = extractedSuite,
                holder = holder,
                isVcdm2 = isVcdm2
            )
            vpTokenSigningPayloads[identifier] = vpPayload
            unsignedVPTokens.addAll(tokens)
        }

        return Pair(vpTokenSigningPayloads, unsignedVPTokens)
    }

    private fun buildPayloadAndUnsignedVPToken(
        identifier: String,
        verifiableCredentials: List<Any>,
        signatureSuite: String,
        holder: String,
        isVcdm2: Boolean
    ): Pair<Any, List<UnsignedVPToken>> {
        val cryptoAlgorithm = resolveJWSAlgorithm(holder, className)
        val cryptosuite = if (isVcdm2) {
            when (cryptoAlgorithm) {
                "EdDSA" -> EDDSA_RDFC_2022
                "ES256" -> ECDSA_RDFC_2019
                else -> throw OpenID4VPExceptions.UnsupportedVcdm2HolderKey(cryptoAlgorithm, className)
            }
        } else null

        val context = mutableListOf(if (isVcdm2) VCDM_V2_CONTEXT else VCDM_V1_CONTEXT)

        if (signatureSuite == Ed25519Signature2020.value) {
            context.add("https://w3id.org/security/suites/ed25519-2020/v1")
        }
        if (signatureSuite == JsonWebSignature2020.value) {
            context.add("https://w3id.org/security/suites/jws-2020/v1")
        }

        val vpTokenSigningPayload = LdpVPToken(
            context = context,
            type = listOf("VerifiablePresentation"),
            verifiableCredential = verifiableCredentials,
            id = this.id,
            holder = holder,
            proof = Proof(
                type = if (isVcdm2) DataIntegrityProof.value else signatureSuite,
                challenge = authorizationRequest.nonce,
                domain = authorizationRequest.clientId,
                verificationMethod = holder,
                proofPurpose = if (isVcdm2) "authentication" else null,
                cryptosuite = cryptosuite
            )
        )

        val vpTokenSigningPayloadString = encodeToJsonString(
            vpTokenSigningPayload,
            "vpTokenSigningPayload",
            LdpVPToken::class.java.simpleName
        )

        val dataToSign: ByteArray = if (isVcdm2) {
            RDFC10Canonicalization.canonicalizeDataIntegrity(vpTokenSigningPayloadString)
        } else {
            val canonicalDataBase64Url = URDNA2015Canonicalization.canonicalize(vpTokenSigningPayloadString)
            when (signatureSuite) {
                JsonWebSignature2020.value, Ed25519Signature2018.value -> {
                val headerMap = mapOf(
                    "alg" to cryptoAlgorithm,
                    "crit" to listOf("b64"),
                    "b64" to false
                )
                val headerJson = encodeToJsonString(headerMap, "jwsHeader", className)
                val headerBase64Url = encodeToBase64Url(headerJson.toByteArray(Charsets.UTF_8))
                val rawPayloadBytes = decodeFromBase64Url(canonicalDataBase64Url)
                headerBase64Url.toByteArray(Charsets.UTF_8) + byteArrayOf(0x2E.toByte()) + rawPayloadBytes
                }
                else -> decodeFromBase64Url(canonicalDataBase64Url)
            }
        }

        val unsignedVPToken = UnsignedVPToken(
            id = identifier,
            format = FormatType.LDP_VC,
            holderKeyReference = holder,
            signatureAlgorithm = cryptoAlgorithm,
            dataToSign = dataToSign
        )

        return Pair(vpTokenSigningPayload, listOf(unsignedVPToken))
    }

    companion object {
        @Suppress("UNCHECKED_CAST")
        internal fun extractHolderAndSignatureSuite(credential: Any): Pair<String, String> {
            val credentialMap = credential as? Map<String, Any>
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Credential is not a valid JSON object", className
                )

            val credentialSubject = credentialMap["credentialSubject"] as? Map<String, Any>
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Holder ID not available in the credential", className
                )

            val holderId = credentialSubject["id"] as? String
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Holder ID not available in the credential", className
                )

            return Pair(
                holderId,
                if (isVcdm2Credential(credential, className)) DataIntegrityProof.value else JsonWebSignature2020.value
            )
        }

        internal fun validateHolderId(holderId: String): String {
            val hasValidDidSyntax = SUPPORTED_HOLDER_DID_PATTERN.matches(holderId)
            val hasValidDidKeyFragment = if (holderId.startsWith("did:key:") && holderId.contains('#')) {
                val fingerprint = holderId.substringAfter("did:key:").substringBefore('#')
                val fragment = holderId.substringAfter('#')
                fragment == fingerprint
            } else {
                true
            }

            if (!hasValidDidSyntax || !hasValidDidKeyFragment) {
                throw OpenID4VPExceptions.InvalidData(
                    "Holder ID must be a valid did:jwk, did:key, or did:web identifier: $holderId",
                    className
                )
            }

            return holderId
        }
    }
}

@JsonSerialize(using = LdpVcTokenSerializer::class)
internal data class LdpVcToken(val verifiableCredential: Any) : VPToken

internal class LdpVcTokenSerializer : JsonSerializer<LdpVcToken>() {
    override fun serialize(value: LdpVcToken, gen: JsonGenerator, serializers: SerializerProvider) {
        serializers.defaultSerializeValue(value.verifiableCredential, gen)
    }
}
