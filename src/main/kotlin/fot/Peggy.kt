package fot

import fot.ResponseItem.BlindedAttestersAndSalt
import fot.ResponseItem.BlindingFactor
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

    /**
     * Step Two
     *
     * - Peggy gets Victor's message from step 1 and PGP-verifies it
     * - Peggy recovers data from his saved session and the message from Victor.
     * - Peggy generates a vector of **k** blinding factors
     * - Peggy uses the vector of blinding factors to generate:
     *      - A list of k sets of her attesters blinded
     *      - A list of k sets of hashes of her attesters blinded (plus salt)       --| Commitments
     *      - A list of k sets of hashes of Victor's blinded verifiers re-blinded   --| Commitments
     *      - **attesters hashes and re-blinded verifiers hashes = Peggy's commitments**
     *  - Peggy stores her session:
     *      - session id,
     *      - Victor's blinded verifiers set,
     *      - list of sets of blinded attesters,
     *      - vector of blinding factors,
     *      - salt,
     *      - list of sets of blinded attester hashes,
     *      - list of sets of hashes of Victor's verifiers re-blinded,
     *      - message Peggy wants to prove.
     *  - Peggy pgp-signs and sends a message to Victor with:
     *      - session id
     *      - her pgp public key (TOFU)
     *      - list of k sets of her attesters blinded
     *      - list of k sets of hashes of Victor's verifiers re-blinded
     *      - the message Peggy wants to prove.
     */
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
            sessionId = sessionId,
            blindedVerifiers = blindedVerifiers,
            blindedAttesters = blindedAttesters,
            blindingFactors = blindingFactors,
            salt = salt,
            blindedAttesterHashes = blindedAttesterHashes,
            reBlindedVerifierHashes = reBlindedVerifierHashes,
            message = message
        )
        store(session)
        return StepTwoMessage(
            sessionId = sessionId,
            pgpPublicKey = pgpPublicKey,
            blindedAttesterHashes = blindedAttesterHashes,
            reBlindedVerifierHashes = reBlindedVerifierHashes,
            message = message,
            pgpSignature = signatureStepTwo
        )
    }

    /**
     * Step Four
     * - Peggy gets Victor's message from step 3 and PGP-verifies it
     * - Peggy recovers data from his saved session and the message from Victor.
     * - Peggy iterates the challenge vector from Victor:
     *      - when vector element is 0, she adds to the response the blind factor used
     *      to generate the commitment set at that position in the commitment lists.
     *      - when vector element is 1, she adds to the response the blinded attesters set
     *      and the salt used to generate the commitment set at that position in the commitment lists.
     *
     * - Peggy stores her session: new values are Victor's challenge vector and her response.
     * - Peggy pgp-signs and sends a message to Victor with:
     *      - session id
     *      - response
     */
    fun stepFour(stepThreeMessage: StepThreeMessage): StepFourMessage {
        assert(pgpVerify(stepThreeMessage.pgpSignature, victorPgpPublicKey, stepThreeMessage.challenge))
        val session = sessions.first { it.sessionId == stepThreeMessage.sessionId }
        val sessionId = session.sessionId
        val blindingFactors = session.blindingFactors
        val blindedAttesters = session.blindedAttesters
        val salt = session.salt
        val challenge = stepThreeMessage.challenge

        val response = mutableListOf<ResponseItem>()
        repeat(k) { i ->
            if (challenge[i] == 0) {
                response.add(BlindingFactor(blindingFactors[i]))
            } else {
                response.add(BlindedAttestersAndSalt(blindedAttesters[i], salt[i]))
            }
        }
        val newSession = session.copy(
            challenge = challenge,
            response = response
        )
        store(newSession)
        val signatureStepFour = pgpSign("$sessionId@#~${Json.encodeToString(response)}", pgpPrivateKey)
        return StepFourMessage(
            sessionId = sessionId,
            response = response,
            pgpSignature = signatureStepFour
        )
    }

    private fun store(session: PeggySession) {
        sessions.removeIf { it.sessionId == session.sessionId }
        sessions.add(session)
    }
}

data class PeggySession(
    val sessionId: String,
    val blindedVerifiers: Set<FotPublicKey>,
    val blindedAttesters: List<Set<Attester>>,
    val blindingFactors: List<Double>,
    val salt: List<String>,
    val blindedAttesterHashes: List<Set<String>>,
    val reBlindedVerifierHashes: List<Set<String>>,
    val message: Message,
    val challenge: List<Int> = emptyList(),
    val response: List<ResponseItem> = emptyList(),
)