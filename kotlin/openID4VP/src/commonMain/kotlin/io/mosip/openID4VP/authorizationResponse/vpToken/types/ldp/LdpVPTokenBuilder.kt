package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.LdpVcToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.getUnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.getVPTokenSigningResult
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.createNestedPath
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToMultibaseBase58btc
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private val className = LdpVPTokenBuilder::class.simpleName!!

internal class LdpVPTokenBuilder : VPTokenBuilder {
    override fun build(
        credentialInputDescriptorMappings: List<CredentialInputDescriptorMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        rootIndex: Int
    ): Triple<List<VPToken>, List<DescriptorMap>, Int> {
        if (vpTokenSigningResults.isEmpty()) {
            throw OpenID4VPExceptions.MissingInput(
                "",
                "Missing LDP signature",
                className
            )
        }
        if (vpTokenSigningResults.size != credentialInputDescriptorMappings.size) {
            throw OpenID4VPExceptions.InvalidData(
                "LDP signing results count does not match selected credentials count",
                className
            )
        }

        val ldpVPTokenPayloads = unsignedVPTokenResult.first as? Map<*, *>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected List<LdpVPToken> as payload",
                className
            )
        val unsignedVPTokens = unsignedVPTokenResult.second

        if (ldpVPTokenPayloads.size != credentialInputDescriptorMappings.size ||
            unsignedVPTokens.size != credentialInputDescriptorMappings.size
        ) {
            throw OpenID4VPExceptions.InvalidData(
                "LDP unsigned VP token count does not match selected credentials count",
                className
            )
        }

        val vpTokens: List<LdpVPToken> = credentialInputDescriptorMappings.indices.map { index ->
            val credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            val identifier =  credentialInputDescriptorMapping.identifier ?: throw OpenID4VPExceptions.InvalidData(
                "Identifier is expected in the credential request id mapping",
                className
            )

            val ldpVPTokenPayload = ldpVPTokenPayloads[identifier] as? LdpVPToken
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Expected LdpVPToken as payload",
                    className
                )
            buildVPToken(
                ldpVPTokenPayload,
                vpTokenSigningResults,
                unsignedVPTokens,
                identifier
            )
        }

        val descriptorMaps = credentialInputDescriptorMappings.mapIndexed { index, mapping ->
            DescriptorMap(
                id = mapping.inputDescriptorId,
                format = VPFormatType.LDP_VP.value,
                path = "$[${rootIndex + index}]",
                pathNested = createNestedPath(
                    mapping.inputDescriptorId,
                    mapping.nestedPath,
                    FormatType.LDP_VC
                )
            )
        }
        return Triple(vpTokens, descriptorMaps, rootIndex + vpTokens.size)
    }

    override fun build(
        credentialToCredentialQueryIdMappings: List<CredentialToCredentialQueryIdMapping>,
        unsignedVPTokenResult: Pair<Map<String, Any>, List<UnsignedVPToken>>,
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<String, List<VPToken>> {
        val unsignedVPTokens = unsignedVPTokenResult.second
        val vpTokenResult = mutableMapOf<String, MutableList<VPToken>>()

        @Suppress("UNCHECKED_CAST")
        val payloadMap = unsignedVPTokenResult.first as? Map<String, Any>
            ?: throw OpenID4VPExceptions.InvalidData(
                "Expected Map<String, Any> as payload for DCQL LDP flow",
                className
            )

        for (mapping in credentialToCredentialQueryIdMappings) {
            val identifier = mapping.identifier
                ?: throw OpenID4VPExceptions.InvalidData(
                    "Missing identifier in credential mapping", className
                )

            val payload = payloadMap[identifier]
                ?: throw OpenID4VPExceptions.InvalidData(
                    "No payload found for identifier: $identifier", className
                )

            val vpToken: VPToken = when (payload) {
                is LdpVPToken -> {
                    buildVPToken(payload, vpTokenSigningResults, unsignedVPTokens, identifier)
                }
                is LdpVcToken -> payload
                else -> throw OpenID4VPExceptions.InvalidData(
                    "Unexpected payload type: ${payload::class.simpleName}", className
                )
            }

            vpTokenResult.getOrPut(mapping.credentialQueryId) { mutableListOf() }
                .add(vpToken)
        }

        return vpTokenResult
    }

    private fun buildVPToken(
        ldpVPTokenPayload: LdpVPToken,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        unsignedVPTokens: List<UnsignedVPToken>,
        identifier: String
    ): LdpVPToken {
        val proof = ldpVPTokenPayload.proof!!
        val proofType = proof.type

        val unsignedVPToken = getUnsignedVPToken(unsignedVPTokens, identifier, className)
        val vpTokenSigningResult = getVPTokenSigningResult(vpTokenSigningResults, identifier, className)

        when (proofType) {
            SignatureSuiteAlgorithm.JsonWebSignature2020.value,
            SignatureSuiteAlgorithm.Ed25519Signature2018.value -> {
                val signingInputBytes = unsignedVPToken.dataToSign
                val dotIndex = signingInputBytes.indexOf(0x2E.toByte())
                val headerBase64Url = String(signingInputBytes.sliceArray(0 until dotIndex))
                val signatureBase64Url = encodeToBase64Url(vpTokenSigningResult.signedData)
                proof.jws = "$headerBase64Url..$signatureBase64Url"
            }
            SignatureSuiteAlgorithm.RSASignature2018.value -> {
                val signatureBase64Url = encodeToBase64Url(vpTokenSigningResult.signedData)
                proof.signatureValue = signatureBase64Url
            }
            SignatureSuiteAlgorithm.DataIntegrityProof.value -> {
                if (vpTokenSigningResult.signedData.size != 64) {
                    throw OpenID4VPExceptions.InvalidSignature(
                        "Data Integrity Ed25519 and P-256 signatures must be exactly 64 bytes",
                        className
                    )
                }
                proof.proofValue = encodeToMultibaseBase58btc(vpTokenSigningResult.signedData)
            }
            else -> {
                proof.proofValue = encodeToMultibaseBase58btc(vpTokenSigningResult.signedData)
            }
        }

        return LdpVPToken(
            ldpVPTokenPayload.context,
            ldpVPTokenPayload.type,
            ldpVPTokenPayload.verifiableCredential,
            ldpVPTokenPayload.id,
            ldpVPTokenPayload.holder,
            proof
        )
    }
}