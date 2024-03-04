package victor

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.random.Random

class Victor {
    private val participants: Participants = Participants(prover = "Peggy", verifier = "Victor")
    private val trustedVerifiers = listOf<PublicKey>(
        PublicKey("WalterPUblicKey"),
    )
    private val message = Message(from = "Peggy", to = "Walter", content = "messageContent")
    private val publicKey = PublicKey("VictorPublicKey")
    private val privateKey = PrivateKey("VictorPrivateKey")
    private val sessions = mutableListOf<VictorSession>()


    fun stepOne(): StepOneMessage {
        val blindFactor = blindFactGen()
        val blindedVerifiers = mutableListOf<PublicKey>()
        trustedVerifiers.forEach { pk ->
            blindedVerifiers.add(blindPublicKey(pk, blindFactor))
        }
        val sessionId = (Json.encodeToString(participants) + Json.encodeToString(message)).hashCode().toString()
        val signatureStepOne = pgpSign("$sessionId@#~${Json.encodeToString(blindedVerifiers)}", privateKey)
        val session = VictorSession(
            sessionId,
            blindFactor,
            blindedVerifiers,
            publicKey
        )
        store(session)
        return StepOneMessage(sessionId, publicKey, blindedVerifiers, signatureStepOne)
    }

    private fun store(session: VictorSession) {
        sessions.add(session)
    }
}

fun blindFactGen(): Double = Random.nextDouble()

data class StepOneMessage(
    val sessionId: String,
    val publicKey: PublicKey,
    val blindedVerifiers: List<PublicKey>,
    val signature: Signature,
)

fun blindPublicKey(publicKey: PublicKey, blindFactor: Double): PublicKey {
    return PublicKey(publicKey.key, publicKey.blindFactor + blindFactor)
}

fun blindSignature(signature: Signature, blindFactor: Double): Signature {
    return Signature(signature.signature, signature.blindFactor + blindFactor)
}

fun blindAttester(attester: Attester, blindFactor: Double): Attester {
    return Attester(blindSignature(attester.signature, blindFactor), blindPublicKey(attester.publicKey, blindFactor))
}


fun pgpSign(input: String, privateKey: PrivateKey): Signature {
    return Signature("$privateKey@#~$input")
}

fun pgpVerify(signature: Signature, publicKey: PublicKey, content: Any): Boolean {
    return true
}

@Serializable
data class Participants(
    val prover: String,
    val verifier: String,
)

data class VictorSession(
    val sessionId: String,
    val blindFactor: Double,
    val blindedVerifiers: List<PublicKey>,
    val publicKey: PublicKey,
)

@Serializable
data class PublicKey(val key: String, val blindFactor: Double = 0.0)
data class PrivateKey(val key: String)
@Serializable
data class Signature(val signature: String, val blindFactor: Double = 0.0)

@Serializable
data class Message(val from: String, val to: String, val content: String)

@Serializable
data class Attester(val signature: Signature, val publicKey: PublicKey)

val walterPublicKey = PublicKey("WalterPublicKey")
val walterPrivateKey = PrivateKey("WalterPrivateKey")
private val message = Message(from = "Peggy", to = "Walter", content = "messageContent")
val messageSignature = pgpSign(Json.encodeToString(message), walterPrivateKey)

class Peggy {
    private val attesters = mutableMapOf<Message, Attester>().apply {
        this[message] = Attester(messageSignature, walterPublicKey)
    }
    private val message = Message(from = "Peggy", to = "Walter", content = "messageContent")
    private val publicKey = PublicKey("PeggyPublicKey")
    private val privateKey = PrivateKey("PeggyPrivateKey")
    private val sessions = mutableListOf<PeggySession>()

    fun stepTwo(stepOneMessage: StepOneMessage, k: Int): StepTwoMessage {
        val sessionId = stepOneMessage.sessionId
        val victorPublicKey = stepOneMessage.publicKey
        val signatureStepOne = stepOneMessage.signature
        pgpVerify(signatureStepOne, victorPublicKey, stepOneMessage.blindedVerifiers)
        val blindedVerifiers = stepOneMessage.blindedVerifiers
        val blindingFactors = mutableListOf<Double>()
        val salt = mutableListOf<Double>()
        val blindedAttesters = mutableListOf<Set<Attester>>()
        val blindedSignatureHashes = mutableListOf<Set<String>>()
        val reBlindedVerifierPkHashes = mutableListOf<Set<String>>()
        repeat(k) { i ->
            blindingFactors.add(blindFactGen())
            salt.add(Random.nextDouble())
            val blindedAtts = mutableSetOf<Attester>()
            val blindedAttHashes = mutableSetOf<String>()
            val reblindedVerifierHashes = mutableSetOf<String>()
            attesters.values.forEach { attester ->
                val blindedAttester = blindAttester(attester, blindingFactors[i])
                blindedAtts.add(blindedAttester)
                blindedAttHashes.add((Json.encodeToString(blindedAttester) + salt[i]).hashCode().toString())
            }
            blindedVerifiers.forEach { publicKey ->
                reblindedVerifierHashes.add(Json.encodeToString(blindPublicKey(publicKey, blindingFactors[i])).hashCode().toString())
            }
            blindedAttesters.add(blindedAtts)
            blindedSignatureHashes.add(blindedAttHashes)
            reBlindedVerifierPkHashes.add(reblindedVerifierHashes)
        }
        val signatureStepTwo = pgpSign(
            sessionId +
                    "@#~${Json.encodeToString(publicKey)}" +
                    "@#~${Json.encodeToString(blindedSignatureHashes)}" +
                    "@#~${Json.encodeToString(reBlindedVerifierPkHashes)}" +
                    "@#~${Json.encodeToString(message)}",
            privateKey
        )
        val session = PeggySession(
            sessionId,
            blindedVerifiers,
            blindedAttesters,
            blindingFactors,
            salt,
            blindedSignatureHashes,
            reBlindedVerifierPkHashes,
            message
        )
        store(session)
        return StepTwoMessage(
            sessionId,
            publicKey,
            blindedSignatureHashes,
            reBlindedVerifierPkHashes,
            message,
            signatureStepTwo
        )
    }

    private fun store(session: PeggySession) {
        sessions.add(session)
    }
}

data class StepTwoMessage(
    val sessionId: String,
    val publicKey: PublicKey,
    val blindedSignatureHashes: List<Set<String>>,
    val reBlindedVerifierPkHashes: List<Set<String>>,
    val message: Message,
    val signature: Signature,
)

data class PeggySession(
    val sessionId: String,
    val blindedVerifiers: List<PublicKey>,
    val blindedAttesters: List<Set<Attester>>,
    val blindingFactors: List<Double>,
    val salt: List<Double>,
    val blindedSignatureHashes: List<Set<String>>,
    val reBlindedVerifierPkHashes: List<Set<String>>,
    val message: Message,
)

class FotDemo {
    private lateinit var peggy: Peggy
    private lateinit var victor: Victor
    private val messages = mutableListOf<Any>()
    private val k = 3

    fun fot() {
        stepOne()
        stepTwo(messages[0] as StepOneMessage)
    }


    fun stepOne() {
        peggy = Peggy()
        victor = Victor()
        val stepOneMessage = victor.stepOne()
        messages.add(stepOneMessage)
    }

    fun stepTwo(stepOneMessage: StepOneMessage) {
        val stepTwoMessage = peggy.stepTwo(stepOneMessage, k)
        messages.add(stepTwoMessage)
    }
}



fun main() {

}