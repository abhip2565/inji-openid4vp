package io.mosip.openID4VP.common

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class RDFC10CanonicalizationTest {
    private val context = """
        {
          "@version": 1.1,
          "id": "@id",
          "type": "@type",
          "VerifiablePresentation": "https://www.w3.org/2018/credentials#VerifiablePresentation",
          "holder": {"@id": "https://www.w3.org/2018/credentials#holder", "@type": "@id"},
          "proof": "https://w3id.org/security#proof",
          "DataIntegrityProof": "https://w3id.org/security#DataIntegrityProof",
          "cryptosuite": "https://w3id.org/security#cryptosuite",
          "verificationMethod": {"@id": "https://w3id.org/security#verificationMethod", "@type": "@id"},
          "proofPurpose": {"@id": "https://w3id.org/security#proofPurpose", "@type": "@vocab"},
          "authentication": "https://w3id.org/security#authentication",
          "challenge": "https://w3id.org/security#challenge",
          "domain": "https://w3id.org/security#domain",
          "proofValue": "https://w3id.org/security#proofValue"
        }
    """.trimIndent()

    @Test
    fun `RDFC hash data is 64 bytes and excludes proofValue`() {
        val first = RDFC10Canonicalization.canonicalizeDataIntegrity(document("zFirst", "nonce"))
        val second = RDFC10Canonicalization.canonicalizeDataIntegrity(document("zSecond", "nonce"))

        assertEquals(64, first.size)
        assertContentEquals(first, second)
    }

    @Test
    fun `RDFC hash data protects proof configuration`() {
        val first = RDFC10Canonicalization.canonicalizeDataIntegrity(document("zValue", "nonce-1"))
        val second = RDFC10Canonicalization.canonicalizeDataIntegrity(document("zValue", "nonce-2"))

        assertFalse(first.contentEquals(second))
    }

    @Test
    fun `rejects multiple data integrity proofs`() {
        val multipleProofs = document("zValue", "nonce")
            .replace("\"proof\": {", "\"proof\": [{")
            .replace("          }\n        }", "          }]\n        }")

        val exception = assertFailsWith<IllegalArgumentException> {
            RDFC10Canonicalization.canonicalizeDataIntegrity(multipleProofs)
        }

        assertEquals("Multiple Data Integrity proofs are not supported", exception.message)
    }

    private fun document(proofValue: String, challenge: String) = """
        {
          "@context": $context,
          "type": ["VerifiablePresentation"],
          "holder": "did:example:holder",
          "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "verificationMethod": "did:example:holder#key-1",
            "proofPurpose": "authentication",
            "challenge": "$challenge",
            "domain": "https://verifier.example",
            "proofValue": "$proofValue"
          }
        }
    """.trimIndent()
}
