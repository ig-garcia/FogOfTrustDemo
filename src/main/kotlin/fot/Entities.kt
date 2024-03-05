package fot

import kotlinx.serialization.Serializable

@Serializable
data class Participants(
    val prover: String,
    val verifier: String,
)

@Serializable
data class PgpPublicKey(val key: String, val blindFactor: Double = 0.0)
data class PgpPrivateKey(val key: String)
@Serializable
data class PgpSignature(val signature: String, val blindFactor: Double = 0.0)

@Serializable
data class FotPublicKey(val key: String, val blindFactor: Double = 0.0)
data class FotPrivateKey(val key: String)
@Serializable
data class FotSignature(val signature: String, val blindFactor: Double = 0.0)

@Serializable
data class Message(val from: String, val to: String, val content: String)

@Serializable
data class Attester(val fotSignature: FotSignature, val fotPublicKey: FotPublicKey)

@Serializable
sealed interface ResponseItem {
    @Serializable
    data class BlindingFactor(val blindingFactor: Double): ResponseItem
    @Serializable
    data class BlindedAttestersAndSalt(
        val blindedAttesters: Set<Attester>,
        val salt: String,
    ): ResponseItem
}