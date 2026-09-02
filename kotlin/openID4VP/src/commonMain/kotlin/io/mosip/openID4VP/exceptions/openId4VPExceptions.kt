package io.mosip.openID4VP.exceptions

import io.mosip.openID4VP.authorizationResponse.AuthorizationErrorResponse
import io.mosip.openID4VP.verifier.VerifierResponse
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.OpenID4VPErrorCodes.INVALID_REQUEST
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR
import io.mosip.openID4VP.common.OpenID4VPErrorFields.ERROR_DESCRIPTION
import java.util.logging.Level
import java.util.logging.Logger

sealed class OpenID4VPExceptions(
    val errorCode: String,
    override val message: String,
    val className: String,
    // holds the response received from the Verifier if the error is sent to the Verifier
    var verifierResponse: VerifierResponse? = null,
    // whether this error should be dispatched to the Verifier; defaults to true
    val notifyVerifier: Boolean = true,
    cause: Throwable? = null
) : Exception("$errorCode : $message", cause) {

    internal fun setVerifierResponse(response: VerifierResponse) {
        verifierResponse = response
    }

    init {
        Logger.getLogger(className).log(Level.SEVERE,"ERROR [$errorCode] - $message | Class: $className")
    }

    companion object {
        fun error(message: String, className: String) {
            Logger.getLogger(className).log(Level.SEVERE,"ERROR : $message | Class: $className")
        }
    }

    fun toErrorResponse(): MutableMap<String, String> {
        return mutableMapOf(
            ERROR to errorCode,
            ERROR_DESCRIPTION to message
        )
    }

    fun toAuthorizationErrorResponse(state: String?): AuthorizationErrorResponse {
        return AuthorizationErrorResponse(
            error = errorCode,
            errorDescription = message,
            state = state
        )
    }

    // Authorization Exceptions

    class InvalidVerifier(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_CLIENT, message, className)

    class AccessDenied(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.ACCESS_DENIED, message, className)

    class UnsupportedVcdm2HolderKey(algorithm: String, className: String) :
        OpenID4VPExceptions(
            OpenID4VPErrorCodes.ACCESS_DENIED,
            "VC 2.0 presentation sharing supports only Ed25519 and P-256 holder keys; found $algorithm",
            className
        )

    class InvalidTransactionData(message: String, className: String) :
        OpenID4VPExceptions(OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA, message, className)

    class InvalidInputPattern(fieldPath: Any, className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Invalid Input Pattern: ${
                if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath
            } pattern is not matching with OpenId4VP specification",
            className
        )




    class JsonEncodingFailed(fieldPath: Any, errorMessage: String, className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Json encoding failed for $fieldPath due to this error: $errorMessage",
            className
        )

    class DeserializationFailure(fieldPath: Any, errorMessage: String, className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Deserializing for $fieldPath failed due to this error: $errorMessage",
            className
        )

    class InvalidLimitDisclosure(className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Invalid Input: constraints->limit_disclosure value should be preferred",
            className
        )

    class InvalidQueryParams(message: String, className: String) :
        OpenID4VPExceptions(INVALID_REQUEST, message, className)


    // General Exceptions
    class InvalidData(
        message: String,
        className: String,
        code: String? = null,
        notifyVerifier: Boolean = true,
        cause: Throwable? = null
    ) : OpenID4VPExceptions(
        errorCode = code ?: INVALID_REQUEST,
        message = message,
        className = className,
        notifyVerifier = notifyVerifier,
        cause = cause
    )


    class MissingInput(
        fieldPath: Any,
        message: String,
        className: String,
        notifyVerifier: Boolean = true
    ) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            when {
                fieldPath is String && fieldPath.isNotEmpty() ->
                    "Missing Input: $fieldPath param is required"
                fieldPath is List<*> && fieldPath.isNotEmpty() ->
                    "Missing Input: ${fieldPath.joinToString("->")} param is required"
                else -> message
            },
            className,
            notifyVerifier = notifyVerifier
        )

    class InvalidInput(
        fieldPath: Any,
        fieldType: Any?,
        className: String,
        notifyVerifier: Boolean = true
    ) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Invalid Input: ${
                when (fieldType) {
                    "String" -> "${if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath} value cannot be an empty string, null, or an integer"
                    "Boolean" -> "${if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath} value must be either true or false"
                    else -> "${if (fieldPath is List<*> && fieldPath.isNotEmpty()) fieldPath.joinToString("->") else fieldPath} value cannot be empty or null"
                }
            }",
            className,
            notifyVerifier = notifyVerifier
        )


    // JWS Exceptions

    class PublicKeyExtractionFailed(message: String, className: String) :
        OpenID4VPExceptions(INVALID_REQUEST, message, className)

    class UnsupportedPublicKeyType(className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Unsupported Public Key type. Supported: publicKeyMultibase",
            className
        )

    class KidExtractionFailed(message: String, className: String) :
        OpenID4VPExceptions(INVALID_REQUEST, message, className)

    class PublicKeyResolutionFailed(message: String, className: String, code: String? = INVALID_REQUEST) :
        OpenID4VPExceptions(INVALID_REQUEST, message, className)

    class InvalidSignature(message: String, className: String) :
        OpenID4VPExceptions(INVALID_REQUEST, message, className)

    class VerificationFailure(message: String, className: String) :
        OpenID4VPExceptions(INVALID_REQUEST, message, className)

    // JWE Exceptions

    class UnsupportedKeyExchangeAlgorithm(className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Required Key exchange algorithm is not supported",
            className
        )

    class UnsupportedOperationException(message: String, className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            message,
            className
        )

    class JweEncryptionFailure(message: String, className: String, cause: Throwable? = null) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            message,
            className,
            cause = cause
        )


    // Exception while sending error to Verifier
    class ErrorDispatchFailure(message: String, className: String) :
        OpenID4VPExceptions(
            OpenID4VPErrorCodes.ERROR_DISPATCH_FAILURE,
            "Failed to send error to verifier: $message",
            className
        )

    //fallback
    class GenericFailure : OpenID4VPExceptions {
        constructor(
            errorCode: String,
            message: String,
            className: String,
        ) : super(errorCode, message, className)

        constructor(
            message: String,
            className: String,
        ) : this(OpenID4VPErrorCodes.SERVER_ERROR, message, className)
    }

    class MismatchingClientIDInRequest(className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            className
        )

    class MismatchingClientIdSchemeInRequest(className: String) :
        OpenID4VPExceptions(
            INVALID_REQUEST,
            "Client Id Scheme mismatch in Authorization Request parameter and the Request Object",
            className
        )

    class VerifiablePresentationConstructionFailure(cause: Throwable, className: String) :
        OpenID4VPExceptions(
            OpenID4VPErrorCodes.SERVER_ERROR,
            "The wallet encountered an internal error while preparing the presentation.",
            className,
            cause = cause
        )

    class AuthorizationResponseConstructionFailure(cause: Throwable, className: String) :
        OpenID4VPExceptions(
            OpenID4VPErrorCodes.SERVER_ERROR,
            "The wallet encountered an internal error while preparing the authorization response.",
            className,
            cause = cause
        )

    class EncodingFailed(errorCode: String = INVALID_REQUEST, message: String, className: String) : OpenID4VPExceptions(
        errorCode,
        "Encoding failed due to this error: $message",
        className
    )
}
