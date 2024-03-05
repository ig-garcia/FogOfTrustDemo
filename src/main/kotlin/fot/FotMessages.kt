package fot

data class StepZeroMessagePeggyToWalter(
    val message: Message,
)

data class StepZeroMessageWalterToPeggy(
    val walterAttester: Attester,
)

data class StepZeroMessageWalterToVictor(
    val walterFotPublicKey: FotPublicKey,
)

data class StepOneMessage(
    val sessionId: String,
    val pgpPublicKey: PgpPublicKey,
    val blindedVerifiers: Set<FotPublicKey>,
    val pgpSignature: PgpSignature,
)

data class StepTwoMessage(
    val sessionId: String,
    val pgpPublicKey: PgpPublicKey,
    val blindedAttesterHashes: List<Set<String>>,
    val reBlindedVerifierHashes: List<Set<String>>,
    val message: Message,
    val pgpSignature: PgpSignature,
)

data class StepThreeMessage(
    val sessionId: String,
    val challenge: List<Int>,
    val pgpSignature: PgpSignature,
)

data class StepFourMessage(
    val sessionId: String,
    val response: List<ResponseItem>,
    val pgpSignature: PgpSignature,
)