package io.mosip.openID4VP.dcql.evaluator

import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.common.taggedCbor24
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.wallet.Credential
import java.io.ByteArrayOutputStream
import java.util.Base64

internal object DCQLTestFixtures {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val objectMapper = getObjectMapper()

    const val VCDM_V1_CONTEXT = "https://www.w3.org/2018/credentials/v1"
    const val VCDM_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"

    fun ldpCredential(
        id: String,
        contexts: List<String>? = listOf(VCDM_V2_CONTEXT),
        holderId: String? = "did:key:z6MkholderKeyFingerprint"
    ): Credential {
        val credentialSubject = mutableMapOf<String, Any>(
            "given_name" to "Alice",
            "family_name" to "Jones"
        )
        holderId?.let { credentialSubject["id"] = it }

        val credentialData = mutableMapOf<String, Any>(
            "type" to listOf("VerifiableCredential", "EmployeeCredential"),
            "credentialSubject" to credentialSubject
        )
        contexts?.let { credentialData["@context"] = it }

        return Credential(
            format = FormatType.LDP_VC,
            data = credentialData,
            credentialId = id
        )
    }

    fun sdJwtCredential(
        id: String,
        vct: String = "https://example.com/employee",
        holderBinding: Boolean = true
    ): Credential {
        val payload = mutableMapOf(
            "vct" to vct,
            "issuing_country" to "DE",
            "issuance_date" to "2025-01-01",
            "given_name" to "Alice",
            "degrees" to listOf(
                mapOf("type" to "B.Tech", "university" to "IIT"),
                mapOf("type" to "M.S.", "university" to "NUS")
            )
        )
        if (holderBinding) {
            payload["cnf"] = mapOf("kid" to "did:example:holder#key-1")
        }
        val header = encoder.encodeToString(objectMapper.writeValueAsBytes(mapOf("alg" to "none")))
        val encodedPayload = encoder.encodeToString(objectMapper.writeValueAsBytes(payload))
        return Credential(format = FormatType.VC_SD_JWT, data = "$header.$encodedPayload.signature", credentialId = id)
    }

    fun mdocCredential(id: String): Credential {
        val cborMap = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
        }
        val output = ByteArrayOutputStream()
        CborEncoder(output).encode(cborMap)
        return Credential(
            format = FormatType.MSO_MDOC,
            data = encoder.encodeToString(output.toByteArray()),
            credentialId = id
        )
    }

    fun w3cCredential(id: String): Credential {
        return Credential(
            format = FormatType.LDP_VC,
            data = mapOf(
                "type" to listOf("VerifiableCredential", "EmployeeCredential"),
                "credentialSubject" to mapOf(
                    "given_name" to "Alice",
                    "family_name" to "Jones",
                    "id" to "did:example:holder"
                )
            ),
            credentialId = id
        )
    }

    fun getDecodedMdoc() : DataItem {
       return cborMapOf(
            "issuerAuth" to cborArrayOf(),
            "namespaces" to cborMapOf(
                "org.iso.18013.5.1" to cborArrayOf(
                    taggedCbor24(
                        cborMapOf(
                            "digestID" to 0,
                            "random" to "random",
                            "elementIdentifier" to "full_name",
                            "elementValue" to "Simon Kelleher"
                        )
                    )
                )
            )
        )
    }
}

