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
    private lateinit var peggyPublicKey: PublicKey


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

    fun stepThree(stepTwoMessage: StepTwoMessage): StepThreeMessage {
        pgpVerify(stepTwoMessage.signature, stepTwoMessage.publicKey, stepTwoMessage.reBlindedVerifierPkHashes)
        peggyPublicKey = stepTwoMessage.publicKey
        val session = sessions.first { it.sessionId == stepTwoMessage.sessionId }
        val k = stepTwoMessage.blindedSignatureHashes.size
        val challenge = session.challenge.toMutableList()
        if (challenge.isEmpty()) {
            repeat(k) {
                val randomBit = Random.nextInt(2)
                challenge.add(randomBit)
            }
        }
        val sessionId = session.sessionId
        val signatureStepThree = pgpSign("$sessionId@#~${Json.encodeToString(challenge)}", privateKey)
        val newSession = VictorSession(
            sessionId = sessionId,
            blindFactor = session.blindFactor,
            blindedVerifiers = session.blindedVerifiers,
            publicKey = publicKey, // here in reality we would not save the public key according to the thesis.
            challenge = challenge,
            blindedSignatureHashes = stepTwoMessage.blindedSignatureHashes,
            reBlindedVerifierPkHashes = stepTwoMessage.reBlindedVerifierPkHashes,
            message = message
        )
        store(newSession)
        return StepThreeMessage(
            sessionId,
            challenge,
            signatureStepThree
        )
    }

    fun stepFive(stepFourMessage: StepFourMessage): Set<String> {
        pgpVerify(stepFourMessage.signature, peggyPublicKey, stepFourMessage.response)
        val sessionId = stepFourMessage.sessionId
        val session = sessions.first { it.sessionId == sessionId }
        val challenge = session.challenge
        val response = stepFourMessage.response
        val peggyReblindedVerifiers = session.reBlindedVerifierPkHashes
        val peggyBlindedSignatureHashes = session.blindedSignatureHashes
        assert(challenge.isNotEmpty())
        var trust: Set<String> = setOf("-1")
        val victorBlindFactor = session.blindFactor
        val k = challenge.size
        repeat(k) { i ->
            if (challenge[i] == 0) {
                val peggyBlindingFactor = response[i] as Double
                val reblindedVerifierPkHashes = mutableSetOf<String>()
                trustedVerifiers.forEach { verifierKey ->
                    reblindedVerifierPkHashes.add(hashFunction(blindPublicKey(verifierKey, peggyBlindingFactor)))
                }
                assert(reblindedVerifierPkHashes == peggyReblindedVerifiers[i])
            } else {
                val (peggyBlindedAttesters, salt) = response[i] as BlindedAttestersAndSalt
                val reblindedAttesterHashes = mutableSetOf<String>()
                val blindedAttesterHashes = mutableSetOf<String>()
                peggyBlindedAttesters.forEach { attester ->
                    val (_, publicKey) = attester
                    // here verify(signature, publicKey, message) but this is not PGP verify, so our own verification
                    blindedAttesterHashes.add(hashFunction("${Json.encodeToString(attester)}@#~$salt"))
                    reblindedAttesterHashes.add(hashFunction(blindPublicKey(publicKey, victorBlindFactor)))
                }
                assert(blindedAttesterHashes == peggyBlindedSignatureHashes)
                if (trust == setOf("-1")) {
                    trust = reblindedAttesterHashes.intersect(peggyReblindedVerifiers[i]) // assign trust
                } else {
                    assert(trust == reblindedAttesterHashes.intersect(peggyReblindedVerifiers[i])) // verify its same
                }
            }
        }
        return trust
    }

    private fun store(session: VictorSession) {
        sessions.add(session)
    }
}

fun blindFactGen(): Double = Random.nextDouble()

fun hashFunction(what: Any): String {
    return what.hashCode().toString()
}

data class StepOneMessage(
    val sessionId: String,
    val publicKey: PublicKey,
    val blindedVerifiers: List<PublicKey>,
    val signature: Signature,
)

data class StepThreeMessage(
    val sessionId: String,
    val challenge: List<Int>,
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
    val challenge: List<Int> = emptyList(),
    val blindedSignatureHashes: List<Set<String>> = emptyList(),
    val reBlindedVerifierPkHashes: List<Set<String>> = emptyList(),
    val message: Message? = null,
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
    private lateinit var victorPublicKey: PublicKey
    private val k = 3

    fun stepTwo(stepOneMessage: StepOneMessage, k: Int = this.k): StepTwoMessage {
        val sessionId = stepOneMessage.sessionId
        victorPublicKey = stepOneMessage.publicKey
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

    fun stepFour(stepThreeMessage: StepThreeMessage): StepFourMessage {
        pgpVerify(stepThreeMessage.signature, victorPublicKey, stepThreeMessage.challenge)
        val session = sessions.first { it.sessionId == stepThreeMessage.sessionId }
        val sessionId = session.sessionId
        val blindingFactors = session.blindingFactors
        val blindedAttesters = session.blindedAttesters
        val salt = session.salt

        val response = mutableListOf<Any>()
        repeat(k) { i ->
            if (stepThreeMessage.challenge[i] == 0) {
                response.add(session.blindingFactors)
            } else {
                response.add(BlindedAttestersAndSalt(blindedAttesters[i], salt[i]))
            }
        }
        val signatureStepFour = pgpSign("$sessionId@#~${Json.encodeToString(response)}", privateKey)
        return StepFourMessage(
            sessionId = sessionId,
            response = response,
            signature = signatureStepFour
        )
    }

    private fun store(session: PeggySession) {
        sessions.add(session)
    }
}

@Serializable
data class BlindedAttestersAndSalt(
    val blindedAttesters: Set<Attester>,
    val salt: Double,
)

data class StepTwoMessage(
    val sessionId: String,
    val publicKey: PublicKey,
    val blindedSignatureHashes: List<Set<String>>,
    val reBlindedVerifierPkHashes: List<Set<String>>,
    val message: Message,
    val signature: Signature,
)

data class StepFourMessage(
    val sessionId: String,
    val response: List<Any>,
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

    fun fot(): Set<String> {
        stepOne()
        stepTwo(messages[0] as StepOneMessage)
        stepThree(messages[1] as StepTwoMessage)
        stepFour(messages[2] as StepThreeMessage)
        val trust = stepFive(messages[3] as StepFourMessage)
        return trust
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

    fun stepThree(stepTwoMessage: StepTwoMessage) {
        val stepThreeMessage = victor.stepThree(stepTwoMessage)
        messages.add(stepThreeMessage)
    }

    fun stepFour(stepThreeMessage: StepThreeMessage) {
        val stepFourMessage = peggy.stepFour(stepThreeMessage)
        messages.add(stepFourMessage)
    }

    fun stepFive(stepFourMessage: StepFourMessage): Set<String> {
        return victor.stepFive(stepFourMessage)
    }
}



fun main() {

}