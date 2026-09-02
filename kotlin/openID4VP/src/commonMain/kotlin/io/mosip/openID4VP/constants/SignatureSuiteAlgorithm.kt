package io.mosip.openID4VP.constants

enum class SignatureSuiteAlgorithm(val value: String) {
    DataIntegrityProof("DataIntegrityProof"),
    Ed25519Signature2020("Ed25519Signature2020"),
    JsonWebSignature2020("JsonWebSignature2020"),
    Ed25519Signature2018("Ed25519Signature2018"),
    RSASignature2018("RSASignature2018"),
}