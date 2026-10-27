package io.mosip.openID4VP.mdoc

import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.common.MdocCredentialUtils
import io.mosip.openID4VP.common.MdocDeviceResponseUtils
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap

private const val className = "MdocProximity"
private const val DEVICE_RESPONSE_VERSION = "1.0"
private const val STATUS_OK = 0L

// ES256 (r ‖ s on P-256) and EdDSA (Ed25519) signatures are both 64 bytes
private const val SIGNATURE_BYTES = 64

/**
 * Builds the answer to an in-person (ISO/IEC 18013-5 proximity) mdoc request: the DeviceResponse
 * (clause 8.3.2.1.2.2), which the wallet hands to the transport (Tuvali) as it is.
 *
 * The wallet passes each credential with only the data elements to share already in it; nothing
 * is filtered here. Each element must still be exactly as issued, so every item is checked against
 * its digest in the MSO before anything is signed. For each document the wallet is asked, through
 * the sign callback, to sign the mdoc authentication data (clause 9.1.3) with the credential's
 * device key.
 */
object MdocProximity {

    /**
     * [sessionTranscriptBytes] are the SessionTranscriptBytes of the session (#6.24 around the
     * SessionTranscript), exactly as the transport provides them. [credentials] are mdoc
     * credentials as CBOR, one per docType. An error thrown by [sign] fails the call unchanged.
     */
    suspend fun buildDeviceResponse(
        sessionTranscriptBytes: ByteArray,
        credentials: List<ByteArray>,
        sign: suspend (MdocSigningInput) -> ByteArray,
    ): ByteArray {
        val sessionTranscript = MdocDeviceResponseUtils.sessionTranscriptFrom(sessionTranscriptBytes, className)
        val checkedCredentials = credentials.map { credential -> MdocCredentialUtils.readCheckedCredential(credential, className) }
        val docTypes = checkedCredentials.map { it.docType }
        if (docTypes.toSet().size != docTypes.size) {
            throw invalid("Duplicate Mdoc Credentials with same doctype found")
        }

        val documents = checkedCredentials.map { credential ->
            val dataToSign = MdocDeviceResponseUtils.deviceAuthenticationDataToSign(
                sessionTranscript, credential.docType, credential.algorithm
            )
            val signature = sign(MdocSigningInput(credential.holderKeyReference, credential.algorithm, dataToSign))
            if (signature.size != SIGNATURE_BYTES) {
                throw invalid("${credential.algorithm} signature must be $SIGNATURE_BYTES raw bytes, got ${signature.size}")
            }
            MdocDeviceResponseUtils.document(credential.docType, credential.issuerSigned, credential.algorithm, signature)
        }

        val response = CborMap().apply {
            put(UnicodeString("version"), UnicodeString(DEVICE_RESPONSE_VERSION))
            // documents, when present, holds at least one document
            if (documents.isNotEmpty()) put(UnicodeString("documents"), CborArray().apply { documents.forEach { add(it) } })
            put(UnicodeString("status"), UnsignedInteger(STATUS_OK))
        }
        return encodeCbor(response)
    }

    /** As [buildDeviceResponse], with each credential given as base64url-encoded CBOR. */
    @JvmName("buildDeviceResponseFromBase64Url")
    suspend fun buildDeviceResponse(
        sessionTranscriptBytes: ByteArray,
        credentials: List<String>,
        sign: suspend (MdocSigningInput) -> ByteArray,
    ): ByteArray {
        val decoded = credentials.map { credential ->
            try {
                decodeFromBase64Url(credential)
            } catch (exception: IllegalArgumentException) {
                throw invalid("mdoc credential is not base64url", exception)
            }
        }
        return buildDeviceResponse(sessionTranscriptBytes, decoded, sign)
    }

    private fun invalid(message: String, cause: Throwable? = null) =
        OpenID4VPExceptions.InvalidData(message, className, cause = cause)
}
