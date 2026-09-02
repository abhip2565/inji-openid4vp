package io.mosip.openID4VP.authorizationResponse.vpToken.types.ldp

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationResponse.CredentialInputDescriptorMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.encodeToMultibaseBase58btc
import io.mosip.openID4VP.constants.SignatureSuiteAlgorithm
import io.mosip.openID4VP.testData.ldpVPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.constants.FormatType.LDP_VC
import kotlin.test.*
import io.mosip.openID4VP.authorizationResponse.CredentialToCredentialQueryIdMapping
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.LdpVcToken
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertSame

class LdpVPTokenBuilderTest {

    private lateinit var mockLdpPayload: LdpVPToken
    private lateinit var mockUnsignedVPToken: UnsignedVPToken
    private lateinit var mockProof: Proof
    private val testNonce = "test-nonce-123"
    private val mockSignatureBytes = "test-proof-value-123".toByteArray(Charsets.UTF_8)
    private val mockHeaderBase64Url = "eyJhbGciOiJFZERTQSJ9"
    private val mockJwsDataToSign = mockHeaderBase64Url.toByteArray(Charsets.UTF_8) + byteArrayOf(0x2E) + "payload".toByteArray(Charsets.UTF_8)

    @BeforeTest
    fun setUp() {
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers {
            val input = firstArg<ByteArray>()
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(input)
        }

        mockProof = Proof(
            type = "Ed25519Signature2020",
            created = "2023-01-01T12:00:00Z",
            verificationMethod = "did:example:123#key-1",
            proofPurpose = "authentication",
            challenge = testNonce,
            proofValue = null,
            jws = null,
            domain = "example.com"
        )

        mockLdpPayload = LdpVPToken(
            context = listOf("https://www.w3.org/2018/credentials/v1"),
            type = listOf("VerifiablePresentation"),
            verifiableCredential = listOf(mapOf("id" to "vc-1")),
            id = "vpId-123",
            holder = "did:example:123",
            proof = mockProof
        )

        mockUnsignedVPToken = UnsignedVPToken(
            id = "random-uuid",
            format = LDP_VC,
            holderKeyReference = "did:example:123",
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value,
            dataToSign = "dataToSign".toByteArray(Charsets.UTF_8)
        )
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2020 successfully`() {
        val builder = LdpVPTokenBuilder()
        val signingResult = VPTokenSigningResult(
            id = "random-uuid",
            signedData = mockSignatureBytes
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], "input-descriptor-id1")
                    .apply { identifier = "random-uuid" }
            ),
            unsignedVPTokenResult = Pair(mapOf("random-uuid" to mockLdpPayload), listOf(mockUnsignedVPToken)),
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(mockLdpPayload.context, vpToken.context)
        assertEquals(mockLdpPayload.type, vpToken.type)
        assertEquals(mockLdpPayload.verifiableCredential, vpToken.verifiableCredential)
        assertEquals(mockLdpPayload.id, vpToken.id)
        assertEquals(mockLdpPayload.holder, vpToken.holder)
        assertEquals(encodeToMultibaseBase58btc(mockSignatureBytes), vpToken.proof?.proofValue)
        assertEquals(null, vpToken.proof?.jws)
        assertEquals( """DescriptorMap(id=input-descriptor-id1, format=ldp_vp, path=${'$'}[0], pathNested=null)""", descriptorMaps.first().toString())
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build one LDP VP token per selected credential`() {
        val builder = LdpVPTokenBuilder()
        val firstPayload = mockLdpPayload.copy(verifiableCredential = listOf(mockLdpPayload.verifiableCredential[0]))
        val secondCredential = mapOf("id" to "vc-2")
        val secondPayload = mockLdpPayload.copy(verifiableCredential = listOf(secondCredential))
        val firstMapping = CredentialInputDescriptorMapping(
            LDP_VC,
            firstPayload.verifiableCredential[0],
            "input-descriptor-id1"
        ).apply {
            identifier = "uuid-1"
            nestedPath = "$.verifiableCredential[0]"
        }
        val secondMapping = CredentialInputDescriptorMapping(
            LDP_VC,
            secondPayload.verifiableCredential[0],
            "input-descriptor-id2"
        ).apply {
            identifier = "uuid-2"
            nestedPath = "$.verifiableCredential[0]"
        }

        val unsignedToken1 = mockUnsignedVPToken.copy(id = "uuid-1")
        val unsignedToken2 = mockUnsignedVPToken.copy(id = "uuid-2")

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(firstMapping, secondMapping),
            unsignedVPTokenResult = Pair(
                mapOf(
                    "uuid-1" to firstPayload,
                    "uuid-2" to secondPayload
                ),
                listOf(unsignedToken1, unsignedToken2)
            ),
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(id = "uuid-1", signedData = "signature-1".toByteArray()),
                VPTokenSigningResult(id = "uuid-2", signedData = "signature-2".toByteArray())
            ),
            rootIndex = 2
        )

        assertEquals(2, vpTokens.size)
        assertEquals(listOf(firstPayload.verifiableCredential[0]), (vpTokens[0] as LdpVPToken).verifiableCredential)
        assertEquals(listOf(secondPayload.verifiableCredential[0]), (vpTokens[1] as LdpVPToken).verifiableCredential)
        assertEquals("$[2]", descriptorMaps[0].path)
        assertEquals("$[3]", descriptorMaps[1].path)
        assertEquals("$.verifiableCredential[0]", descriptorMaps[0].pathNested?.path)
        assertEquals("$.verifiableCredential[0]", descriptorMaps[1].pathNested?.path)
        assertEquals(4, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with JsonWebSignature2020 successfully`() {
        val signingResult = VPTokenSigningResult(
            id = "random-uuid",
            signedData = mockSignatureBytes
        )
        val jwsProof = Proof(
            type = SignatureSuiteAlgorithm.JsonWebSignature2020.value,
            created = "2023-01-01T12:00:00Z",
            verificationMethod = "did:example:123#key-1",
            challenge = testNonce,
            domain = "example.com"
        )
        val jwsPayload = mockLdpPayload.copy(proof = jwsProof)

        val jwsUnsignedVPToken = UnsignedVPToken(
            id = "random-uuid",
            format = LDP_VC,
            holderKeyReference = "did:example:123",
            signatureAlgorithm = "EdDSA",
            dataToSign = mockJwsDataToSign
        )

        val builder = LdpVPTokenBuilder()

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, jwsPayload.verifiableCredential[0], "input-descriptor-id1")
                    .apply { identifier = "random-uuid" }
            ),
            unsignedVPTokenResult = Pair(mapOf("random-uuid" to jwsPayload), listOf(jwsUnsignedVPToken)),
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        val expectedJws = "$mockHeaderBase64Url..${encodeToBase64Url(mockSignatureBytes)}"
        assertEquals(expectedJws, vpToken.proof?.jws)
        assertEquals(null, vpToken.proof?.proofValue)
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with RSASignature2018 successfully`() {
        val rsaSignatureBytes = "test-rsa-signature".toByteArray(Charsets.UTF_8)
        val rsaSigningResult = VPTokenSigningResult(
            id = "random-uuid",
            signedData = rsaSignatureBytes
        )
        val rsaProof = Proof(
            type = SignatureSuiteAlgorithm.RSASignature2018.value,
            created = "2023-01-01T12:00:00Z",
            verificationMethod = "did:example:123#key-1",
            challenge = testNonce,
            domain = "example.com"
        )
        val rsaPayload = mockLdpPayload.copy(proof = rsaProof)

        val builder = LdpVPTokenBuilder()

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, rsaPayload.verifiableCredential[0], "input-descriptor-id1")
                    .apply { identifier = "random-uuid" }
            ),
            unsignedVPTokenResult = Pair(mapOf("random-uuid" to rsaPayload), listOf(mockUnsignedVPToken)),
            vpTokenSigningResults = listOf(rsaSigningResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(encodeToBase64Url(rsaSignatureBytes), vpToken.proof?.signatureValue)
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should build LdpVPToken with Ed25519Signature2018 successfully`() {
        val edSignatureBytes = "test-ed25519-2018-signature".toByteArray(Charsets.UTF_8)
        val edSigningResult = VPTokenSigningResult(
            id = "random-uuid",
            signedData = edSignatureBytes
        )
        val edProof = Proof(
            type = SignatureSuiteAlgorithm.Ed25519Signature2018.value,
            created = "2023-01-01T12:00:00Z",
            verificationMethod = "did:example:123#key-1",
            challenge = testNonce,
            domain = "example.com"
        )
        val edPayload = mockLdpPayload.copy(proof = edProof)

        val edUnsignedVPToken = UnsignedVPToken(
            id = "random-uuid",
            format = LDP_VC,
            holderKeyReference = "did:example:123",
            signatureAlgorithm = "EdDSA",
            dataToSign = mockJwsDataToSign
        )

        val builder = LdpVPTokenBuilder()

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, edPayload.verifiableCredential[0], "input-descriptor-id1")
                    .apply { identifier = "random-uuid" }
            ),
            unsignedVPTokenResult = Pair(mapOf("random-uuid" to edPayload), listOf(edUnsignedVPToken)),
            vpTokenSigningResults = listOf(edSigningResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        val expectedJws = "$mockHeaderBase64Url..${encodeToBase64Url(edSignatureBytes)}"
        assertEquals(expectedJws, vpToken.proof?.jws)
        assertEquals(1, nextIndex)
    }

    @Test
    fun `should use existing LdpVPToken from testData`() {
        val testToken = ldpVPToken as LdpVPToken
        val payloadCopy = LdpVPToken(
            context = testToken.context,
            type = testToken.type,
            verifiableCredential = testToken.verifiableCredential,
            id = testToken.id,
            holder = testToken.holder,
            proof = testToken.proof?.apply {
                proofValue = null
                jws = null
            }
        )

        val signingResult = VPTokenSigningResult(
            id = "random-uuid",
            signedData = "new-proof-value".toByteArray(Charsets.UTF_8)
        )
        val builder = LdpVPTokenBuilder()

        val unsignedToken = UnsignedVPToken(
            id = "random-uuid",
            format = LDP_VC,
            holderKeyReference = "did:example:123",
            signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value,
            dataToSign = "dataToSign".toByteArray(Charsets.UTF_8)
        )

        val (vpTokens, descriptorMaps, nextIndex) = builder.build(
            credentialInputDescriptorMappings = listOf(
                CredentialInputDescriptorMapping(LDP_VC, payloadCopy.verifiableCredential[0], "input-descriptor-id1")
                    .apply { identifier = "random-uuid" }
            ),
            unsignedVPTokenResult = Pair(mapOf("random-uuid" to payloadCopy), listOf(unsignedToken)),
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )

        val vpToken = ldpVPToken(vpTokens)
        assertEquals(encodeToMultibaseBase58btc("new-proof-value".toByteArray(Charsets.UTF_8)), vpToken.proof?.proofValue)
    }

    @Test
    fun `should handle null proof in unsigned token`() {
        val payloadWithNullProof = mockLdpPayload.copy(proof = null)
        val signingResult = VPTokenSigningResult(
            id = "random-uuid",
            signedData = "some-sig".toByteArray(Charsets.UTF_8)
        )

        val builder = LdpVPTokenBuilder()

        assertFailsWith<NullPointerException> {
            builder.build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], "input-descriptor-id1")
                        .apply { identifier = "random-uuid" }
                ),
                unsignedVPTokenResult = Pair(mapOf("random-uuid" to payloadWithNullProof), listOf(mockUnsignedVPToken)),
                vpTokenSigningResults = listOf(signingResult),
                rootIndex = 0
            )
        }
    }

    @Test
    fun `should throw MissingInput when LDP signature is missing`() {
        val exception = assertFailsWith<io.mosip.openID4VP.exceptions.OpenID4VPExceptions.MissingInput> {
            LdpVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], "input-descriptor-id1")
                        .apply { identifier = "random-uuid" }
                ),
                unsignedVPTokenResult = Pair(mapOf("random-uuid" to mockLdpPayload), listOf(mockUnsignedVPToken)),
                vpTokenSigningResults = emptyList(),
                rootIndex = 0
            )
        }

        assertEquals("Missing LDP signature", exception.message)
    }

    @Test
    fun `should throw InvalidData when extra LDP signatures are provided`() {
        val exception = assertFailsWith<io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData> {
            LdpVPTokenBuilder().build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(LDP_VC, mockLdpPayload.verifiableCredential[0], "input-descriptor-id1")
                        .apply { identifier = "random-uuid" }
                ),
                unsignedVPTokenResult = Pair(mapOf("random-uuid" to mockLdpPayload), listOf(mockUnsignedVPToken)),
                vpTokenSigningResults = listOf(
                    VPTokenSigningResult("random-uuid", "signature-1".toByteArray()),
                    VPTokenSigningResult("random-uuid", "signature-2".toByteArray())
                ),
                rootIndex = 0
            )
        }

        assertEquals("LDP signing results count does not match selected credentials count", exception.message)
    }

    @Test
    fun `should build LdpVPToken using build method and return correct vp token, descriptor map and next index`() {
        val mapping = CredentialInputDescriptorMapping(
            format = LDP_VC,
            credential = mockLdpPayload.verifiableCredential[0],
            inputDescriptorId = "input-descriptor-id1"
        ).apply { identifier = "random-uuid" }
        val signingResult = VPTokenSigningResult(
            id = "random-uuid",
            signedData = mockSignatureBytes
        )
        val unsignedVPTokenResult = Pair(mapOf("random-uuid" to mockLdpPayload), listOf(mockUnsignedVPToken))
        val builder = LdpVPTokenBuilder()
        val result = builder.build(
            credentialInputDescriptorMappings = listOf(mapping),
            unsignedVPTokenResult = unsignedVPTokenResult,
            vpTokenSigningResults = listOf(signingResult),
            rootIndex = 0
        )
        assertNotNull(result)
        assertEquals(1, result.first.size)
        assertEquals(1, result.second.size)
        assertEquals(1, result.third)
        assertEquals("input-descriptor-id1", result.second[0].id)
        assertEquals(io.mosip.openID4VP.constants.VPFormatType.LDP_VP.value, result.second[0].format)
        assertEquals(encodeToMultibaseBase58btc(mockSignatureBytes), (result.first[0] as LdpVPToken).proof?.proofValue)
    }

    private fun ldpVPToken(vpTokens: List<VPToken>): LdpVPToken {
        assertNotNull(vpTokens)
        assertTrue(vpTokens.size == 1)
        val vpToken = vpTokens.first() as LdpVPToken
        return vpToken
    }

    private val builder = LdpVPTokenBuilder()
    private val signatureBytes = "signature-bytes".toByteArray(Charsets.UTF_8)

    private val payload = ldpVPToken(SignatureSuiteAlgorithm.Ed25519Signature2020.value)
    private val unsignedVPToken = UnsignedVPToken(
        id = "id-1",
        format = LDP_VC,
        holderKeyReference = "did:example:123",
        signatureAlgorithm = SignatureSuiteAlgorithm.Ed25519Signature2020.value,
        dataToSign = "dataToSign".toByteArray(Charsets.UTF_8)
    )

    @Test
    fun `builds a signed vp token keyed by credential query id`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
            unsignedVPTokenResult = Pair(mapOf("id-1" to payload), listOf(unsignedVPToken)),
            vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes))
        )

        assertEquals(setOf("employee-card"), result.keys)
        val token = assertIs<LdpVPToken>(result.getValue("employee-card").single())
        assertEquals(listOf("https://www.w3.org/2018/credentials/v1"), token.context)
        assertEquals(listOf("VerifiablePresentation"), token.type)
        assertEquals(listOf(mapOf("id" to "vc-1")), token.verifiableCredential)
        assertEquals("vpId-123", token.id)
        assertEquals("did:example:123", token.holder)

        val proof = assertNotNull(token.proof)
        assertEquals(SignatureSuiteAlgorithm.Ed25519Signature2020.value, proof.type)
        assertEquals("2023-01-01T12:00:00Z", proof.created)
        assertEquals("did:example:123#key-1", proof.verificationMethod)
        assertEquals("authentication", proof.proofPurpose)
        assertEquals("test-nonce-123", proof.challenge)
        assertEquals("example.com", proof.domain)
        assertEquals(encodeToMultibase(signatureBytes), proof.proofValue)
        assertNull(proof.jws)
        assertNull(proof.signatureValue)
    }

    @Test
    fun `signs holder-bound payloads and passes bare vc tokens through in one dcql request`() {
        val vcToken = LdpVcToken(verifiableCredential = mapOf("id" to "vc-2"))

        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(
                dcqlMapping("id-1", "employee-card"),
                dcqlMapping("id-2", "residence-card")
            ),
            unsignedVPTokenResult = Pair(
                mapOf("id-1" to payload, "id-2" to vcToken),
                listOf(unsignedVPToken)
            ),
            vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes))
        )

        val wrapped = assertIs<LdpVPToken>(result.getValue("employee-card").single())
        assertEquals(encodeToMultibase(signatureBytes), wrapped.proof?.proofValue)

        assertSame(vcToken, result.getValue("residence-card").single())
    }

    @Test
    fun `passes an already-signed LdpVcToken payload through untouched`() {
        val vcToken = LdpVcToken(verifiableCredential = mapOf("id" to "vc-1"))

        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
            unsignedVPTokenResult = Pair(mapOf("id-1" to vcToken), emptyList()),
            vpTokenSigningResults = emptyList()
        )

        assertSame(vcToken, result.getValue("employee-card").single())
    }

    @Test
    fun `groups multiple credentials under the same credential query id`() {
        val secondUnsigned = unsignedVPToken.copy(id = "id-2")

        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(
                dcqlMapping("id-1", "employee-card"),
                dcqlMapping("id-2", "employee-card")
            ),
            unsignedVPTokenResult = Pair(
                mapOf("id-1" to payload, "id-2" to ldpVPToken(SignatureSuiteAlgorithm.Ed25519Signature2020.value)),
                listOf(unsignedVPToken, secondUnsigned)
            ),
            vpTokenSigningResults = listOf(
                VPTokenSigningResult(id = "id-1", signedData = signatureBytes),
                VPTokenSigningResult(id = "id-2", signedData = signatureBytes)
            )
        )

        assertEquals(1, result.size)
        assertEquals(2, result.getValue("employee-card").size)
    }

    @Test
    fun `requires an identifier on every dcql credential mapping`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(
                    CredentialToCredentialQueryIdMapping(LDP_VC, mapOf("id" to "vc-1"), "employee-card")
                ),
                unsignedVPTokenResult = Pair(mapOf("id-1" to payload), listOf(unsignedVPToken)),
                vpTokenSigningResults = emptyList()
            )
        }
        assertEquals("Missing identifier in credential mapping", exception.message)
    }

    @Test
    fun `requires a payload for every dcql identifier`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(dcqlMapping("absent", "employee-card")),
                unsignedVPTokenResult = Pair(mapOf("id-1" to payload), listOf(unsignedVPToken)),
                vpTokenSigningResults = emptyList()
            )
        }
        assertEquals("No payload found for identifier: absent", exception.message)
    }

    @Test
    fun `rejects a dcql payload that is neither an LdpVPToken nor an LdpVcToken`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
                unsignedVPTokenResult = Pair(mapOf("id-1" to "unexpected"), listOf(unsignedVPToken)),
                vpTokenSigningResults = emptyList()
            )
        }
        assertEquals("Unexpected payload type: String", exception.message)
    }

    @Test
    fun `signs a dcql JsonWebSignature2020 proof into a detached jws`() {
        val jwsUnsigned = unsignedVPToken.copy(
            dataToSign = "eyJhbGciOiJFZERTQSJ9".toByteArray(Charsets.UTF_8) +
                byteArrayOf(0x2E) + "payload".toByteArray(Charsets.UTF_8)
        )

        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
            unsignedVPTokenResult = Pair(
                mapOf("id-1" to ldpVPToken(SignatureSuiteAlgorithm.JsonWebSignature2020.value)),
                listOf(jwsUnsigned)
            ),
            vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes))
        )

        val token = assertIs<LdpVPToken>(result.getValue("employee-card").single())
        assertEquals(
            "eyJhbGciOiJFZERTQSJ9..${base64Url(signatureBytes)}",
            token.proof?.jws
        )
    }

    @Test
    fun `signs a dcql RSASignature2018 proof into a signature value`() {
        val result = builder.build(
            credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
            unsignedVPTokenResult = Pair(
                mapOf("id-1" to ldpVPToken(SignatureSuiteAlgorithm.RSASignature2018.value)),
                listOf(unsignedVPToken)
            ),
            vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes))
        )

        val token = assertIs<LdpVPToken>(result.getValue("employee-card").single())
        assertEquals(base64Url(signatureBytes), token.proof?.signatureValue)
    }

    @Test
    fun `requires an identifier on every presentation exchange mapping`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialInputDescriptorMappings = listOf(
                    CredentialInputDescriptorMapping(LDP_VC, mapOf("id" to "vc-1"), "input-1")
                ),
                unsignedVPTokenResult = Pair(mapOf("id-1" to payload), listOf(unsignedVPToken)),
                vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes)),
                rootIndex = 0
            )
        }
        assertEquals("Identifier is expected in the credential request id mapping", exception.message)
    }

    @Test
    fun `rejects a presentation exchange (credentialInputDescriptorMappings) payload that is not an LdpVPToken`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialInputDescriptorMappings = listOf(peMapping("id-1", "input-1")),
                unsignedVPTokenResult = Pair(mapOf("id-1" to "unexpected"), listOf(unsignedVPToken)),
                vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes)),
                rootIndex = 0
            )
        }
        assertEquals("Expected LdpVPToken as payload", exception.message)
    }

    @Test
    fun `rejects a presentation exchange unsigned token count mismatch`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            builder.build(
                credentialInputDescriptorMappings = listOf(peMapping("id-1", "input-1")),
                unsignedVPTokenResult = Pair(
                    mapOf("id-1" to payload, "id-2" to payload),
                    listOf(unsignedVPToken)
                ),
                vpTokenSigningResults = listOf(VPTokenSigningResult(id = "id-1", signedData = signatureBytes)),
                rootIndex = 0
            )
        }
        assertEquals(
            "LDP unsigned VP token count does not match selected credentials count",
            exception.message
        )
    }

    private fun base64Url(bytes: ByteArray) =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    // -------------------------------------------------------------------------------------
    // Data Integrity proofs (VC 2.0)
    // -------------------------------------------------------------------------------------

    private fun dataIntegritySigningResult(signatureLength: Int) = builder.build(
        credentialToCredentialQueryIdMappings = listOf(dcqlMapping("id-1", "employee-card")),
        unsignedVPTokenResult = Pair(
            mapOf("id-1" to ldpVPToken(SignatureSuiteAlgorithm.DataIntegrityProof.value)),
            listOf(unsignedVPToken)
        ),
        vpTokenSigningResults = listOf(
            VPTokenSigningResult(id = "id-1", signedData = ByteArray(signatureLength) { it.toByte() })
        )
    )

    @Test
    fun `should encode a 64 byte Data Integrity signature as a multibase proof value`() {
        val signature = ByteArray(64) { it.toByte() }

        val result = dataIntegritySigningResult(signatureLength = 64)

        val token = assertIs<LdpVPToken>(result.getValue("employee-card").single())
        val proof = assertNotNull(token.proof)
        assertEquals(SignatureSuiteAlgorithm.DataIntegrityProof.value, proof.type)
        assertEquals(encodeToMultibase(signature), proof.proofValue)
        assertNull(proof.jws)
        assertNull(proof.signatureValue)
    }

    @Test
    fun `should reject a Data Integrity signature which is not 64 bytes`() {
        listOf(63, 65).forEach { signatureLength ->
            val error = assertFailsWith<OpenID4VPExceptions.InvalidSignature> {
                dataIntegritySigningResult(signatureLength)
            }
            assertTrue(
                error.message!!.contains("must be exactly 64 bytes"),
                "Unexpected message for a $signatureLength byte signature: ${error.message}"
            )
        }
    }

    private fun encodeToMultibase(bytes: ByteArray) =
        io.mosip.openID4VP.common.encodeToMultibaseBase58btc(bytes)

    private fun ldpVPToken(proofType: String) = LdpVPToken(
        context = listOf("https://www.w3.org/2018/credentials/v1"),
        type = listOf("VerifiablePresentation"),
        verifiableCredential = listOf(mapOf("id" to "vc-1")),
        id = "vpId-123",
        holder = "did:example:123",
        proof = Proof(
            type = proofType,
            created = "2023-01-01T12:00:00Z",
            verificationMethod = "did:example:123#key-1",
            proofPurpose = "authentication",
            challenge = "test-nonce-123",
            domain = "example.com"
        )
    )

    private fun dcqlMapping(identifier: String, credentialQueryId: String) =
        CredentialToCredentialQueryIdMapping(LDP_VC, mapOf("id" to "vc-1"), credentialQueryId)
            .apply { this.identifier = identifier }

    private fun peMapping(identifier: String, inputDescriptorId: String) =
        CredentialInputDescriptorMapping(LDP_VC, mapOf("id" to "vc-1"), inputDescriptorId)
            .apply { this.identifier = identifier }
}
