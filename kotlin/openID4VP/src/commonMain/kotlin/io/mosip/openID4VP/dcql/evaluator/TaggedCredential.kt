package io.mosip.openID4VP.dcql.evaluator

import io.mosip.openID4VP.constants.FormatType

internal interface TaggedCredential {
    val credentialFormat: FormatType
    val hasCryptographicHolderBinding: Boolean
}

internal data class W3cTaggedCredential(
    override val credentialFormat: FormatType,
    override val hasCryptographicHolderBinding: Boolean,
    val types: List<String>,
    val holderId: String? = null,
    val isVcdm2: Boolean = false
) : TaggedCredential

internal data class MdocTaggedCredential(
    override val credentialFormat: FormatType = FormatType.MSO_MDOC,
    override val hasCryptographicHolderBinding: Boolean,
    val doctype: String
) : TaggedCredential

internal data class SdJwtTaggedCredential(
    override val credentialFormat: FormatType,
    override val hasCryptographicHolderBinding: Boolean,
    val vct: String
) : TaggedCredential
