package fot

import kotlinx.serialization.Serializable

data class StepZeroMessagePeggyToWalter(
    val message: Message,
)

data class StepZeroMessageWalterToPeggy(
    val walterAttester: Attester,
)

data class StepZeroMessageWalterToVictor(
    val walterFotPublicKey: FotPublicKey,
)

@Serializable
data class StepOneSignedMessage(
    val stepOneMessage: String,
    val pgpPublicKey: PgpPublicKey,
)

@Serializable
data class StepOneMessage(
    val sessionId: String,
    val pgpPublicKey: PgpPublicKey,
    val blindedVerifiers: Set<FotPublicKey>,
)

@Serializable
data class StepTwoSignedMessage(
    val stepTwoMessage: String,
    val pgpPublicKey: PgpPublicKey,
)

@Serializable
data class StepTwoMessage(
    val sessionId: String,
    val pgpPublicKey: PgpPublicKey,
    val blindedAttesterHashes: List<Set<String>>,
    val reBlindedVerifierHashes: List<Set<String>>,
    val message: Message,
)

@Serializable
data class StepThreeMessage(
    val sessionId: String,
    val challenge: List<Int>,
)

@Serializable
data class StepFourMessage(
    val sessionId: String,
    val response: List<ResponseItem>,
)