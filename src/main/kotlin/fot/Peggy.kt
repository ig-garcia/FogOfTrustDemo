package fot

import fot.pgp.pgpSign
import fot.pgp.pgpVerify
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class Peggy(val message: Message) {
    private val attesters = mutableMapOf<Message, MutableSet<Attester>>(message to mutableSetOf()) // attesters are in the scope of a specific messsage
    private val pgpPublicKey = PgpPublicKey("PeggyPublicKey")
    private val pgpPrivateKey = PgpPrivateKey("PeggyPrivateKey")
    private val sessions = mutableListOf<PeggySession>()
    private lateinit var victorPgpPublicKey: PgpPublicKey
    private var k = 0

    fun stepZeroSendMessageToWalter(): StepZeroMessagePeggyToWalter {
        return StepZeroMessagePeggyToWalter(message)
    }

    fun stepZeroAddWalterAttester(stepZeroMessage: StepZeroMessageWalterToPeggy) {
        attesters[message]!!.add(stepZeroMessage.walterAttester)
    }

    fun stepTwo(stepOneMessage: StepOneMessage, k: Int, saltLength: Int): StepTwoMessage {
        this.k = k
        val sessionId = stepOneMessage.sessionId
        // here we get the public key from "TOFU" message from Victor
        victorPgpPublicKey = stepOneMessage.pgpPublicKey
        val signatureStepOne = stepOneMessage.pgpSignature
        assert(pgpVerify(signatureStepOne, victorPgpPublicKey, stepOneMessage.blindedVerifiers))
        val blindedVerifiers = stepOneMessage.blindedVerifiers
        val blindingFactors = mutableListOf<Double>()
        val salt = mutableListOf<String>()
        val blindedAttesters = mutableListOf<Set<Attester>>()
        val blindedAttesterHashes = mutableListOf<Set<String>>()
        val reBlindedVerifierHashes = mutableListOf<Set<String>>()
        repeat(k) { i ->
            blindingFactors.add(blindFactGen())
            salt.add(randomBitsString(saltLength))
            val blindedAttesterSet = mutableSetOf<Attester>()
            val blindedAttesterHashSet = mutableSetOf<String>()
            val reblindedVerifierHashSet = mutableSetOf<String>()
            attesters[message]!!.forEach { attester ->
                val blindedAttester = blindAttester(attester, blindingFactors[i])
                blindedAttesterSet.add(blindedAttester)
                blindedAttesterHashSet.add(fotHash(Json.encodeToString(blindedAttester) + salt[i]))
            }
            blindedVerifiers.forEach { publicKey ->
                reblindedVerifierHashSet.add(fotHash(Json.encodeToString(blindFotPublicKey(publicKey, blindingFactors[i]))))
            }
            blindedAttesters.add(blindedAttesterSet)
            blindedAttesterHashes.add(blindedAttesterHashSet)
            reBlindedVerifierHashes.add(reblindedVerifierHashSet)
        }
        val signatureStepTwo = pgpSign(
            sessionId +
                    "@#~${Json.encodeToString(pgpPublicKey)}" +
                    "@#~${Json.encodeToString(blindedAttesterHashes)}" +
                    "@#~${Json.encodeToString(reBlindedVerifierHashes)}" +
                    "@#~${Json.encodeToString(message)}",
            pgpPrivateKey
        )
        val session = PeggySession(
            sessionId,
            blindedVerifiers,
            blindedAttesters,
            blindingFactors,
            salt,
            blindedAttesterHashes,
            reBlindedVerifierHashes,
            message
        )
        store(session)
        return StepTwoMessage(
            sessionId = sessionId,
            pgpPublicKey = pgpPublicKey,
            blindedAttesterHashes = blindedAttesterHashes,
            reBlindedVerifierHashes,
            message,
            signatureStepTwo
        )
    }

    fun stepFour(stepThreeMessage: StepThreeMessage): StepFourMessage {
        assert(pgpVerify(stepThreeMessage.pgpSignature, victorPgpPublicKey, stepThreeMessage.challenge))
        val session = sessions.first { it.sessionId == stepThreeMessage.sessionId }
        val sessionId = session.sessionId
        val blindingFactors = session.blindingFactors
        val blindedAttesters = session.blindedAttesters
        val salt = session.salt

        val response = mutableListOf<Any>()
        repeat(k) { i ->
            if (stepThreeMessage.challenge[i] == 0) {
                response.add(blindingFactors[i])
            } else {
                response.add(BlindedAttestersAndSalt(blindedAttesters[i], salt[i]))
            }
        }
        val signatureStepFour = pgpSign("$sessionId@#~${Json.encodeToString(response)}", pgpPrivateKey)
        return StepFourMessage(
            sessionId = sessionId,
            response = response,
            pgpSignature = signatureStepFour
        )
    }

    private fun store(session: PeggySession) {
        sessions.add(session)
    }
}

data class PeggySession(
    val sessionId: String,
    val blindedVerifiers: Set<FotPublicKey>,
    val blindedAttesters: List<Set<Attester>>,
    val blindingFactors: List<Double>,
    val salt: List<String>,
    val blindedSignatureHashes: List<Set<String>>,
    val reBlindedVerifierPkHashes: List<Set<String>>,
    val message: Message,
)