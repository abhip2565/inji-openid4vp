package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.cose.CoseSignature1Utils
import co.nstant.`in`.cbor.model.Map as CborMap

private const val ARRAY_OF_FOUR: Byte = 0x84.toByte()
private const val TAG_ENCODED_CBOR = 24L

/**
 * What the mdoc signs for mdoc authentication (ISO/IEC 18013-5 clause 9.1.3.4): the COSE
 * Sig_structure over DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication",
 * SessionTranscript, DocType, DeviceNameSpacesBytes]).
 *
 * [sessionTranscript] is the encoded SessionTranscript and is spliced in exactly as given: the
 * reader rebuilds these bytes from its own copy of the transcript, so they must not be decoded and
 * re-encoded. DeviceNameSpaces is always empty, as Inji returns no device-signed data elements.
 */
internal fun mdocDeviceAuthenticationDataToSign(sessionTranscript: ByteArray, docType: String, alg: String): ByteArray {
    val deviceAuthentication = byteArrayOf(ARRAY_OF_FOUR) +
        encodeCbor(UnicodeString("DeviceAuthentication")) +
        sessionTranscript +
        encodeCbor(UnicodeString(docType)) +
        encodeCbor(emptyDeviceNameSpacesBytes())
    val deviceAuthenticationBytes = encodeCbor(ByteString(deviceAuthentication).apply { setTag(TAG_ENCODED_CBOR) })
    return CoseSignature1Utils.createSignature1Structure(deviceAuthenticationBytes, alg)
}

/** DeviceNameSpacesBytes = #6.24(bstr .cbor {}): no device-signed data elements. */
internal fun emptyDeviceNameSpacesBytes(): ByteString = taggedCbor24(CborMap())
