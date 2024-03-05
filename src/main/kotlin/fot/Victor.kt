package fot

import fot.ResponseItem.*
import fot.pgp.pgpSign
import fot.pgp.pgpVerify
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class Victor(val message: Message, val participants: Participants) {
    private val trustedVerifiers = mutableSetOf<FotPublicKey>()
    private val pgpPublicKey = PgpPublicKey("VictorPublicKey")
    private val pgpPrivateKey = PgpPrivateKey("VictorPrivateKey")
    private val sessions = mutableListOf<VictorSession>()
    private lateinit var peggyPgpPublicKey: PgpPublicKey

    fun stepZeroAddWalterVerifier(stepZeroMessage: StepZeroMessageWalterToVictor) {
        trustedVerifiers.add(stepZeroMessage.walterFotPublicKey)
    }

    /**
     * Step One
     *
     * - Victor generates a blind factor blinds his "trusted verifiers" (attester public keys).
     * - Victor generates session id from participants + message
     * - Victor stores his session: Session id, blind factor, blinded verifiers and his own PGP public key.
     * - Victor signs and sends a message to Peggy with:
     *      - His PGP public key (TOFU)
     *      - Session id
     *      - His blinded verifiers (attester public keys)
     */
    fun stepOne(): StepOneMessage {
        val blindFactor = blindFactGen()
        val blindedVerifiers = mutableSetOf<FotPublicKey>()
        trustedVerifiers.forEach { pk ->
            blindedVerifiers.add(blindFotPublicKey(pk, blindFactor))
        }
        val sessionId = fotHash(Json.encodeToString(participants) + Json.encodeToString(message))
        val signatureStepOne = pgpSign("$sessionId@#~${Json.encodeToString(blindedVerifiers)}", pgpPrivateKey)
        val session = VictorSession(
            sessionId,
            blindFactor,
            blindedVerifiers,
            pgpPublicKey
        )
        store(session)
        return StepOneMessage(sessionId, pgpPublicKey, blindedVerifiers, signatureStepOne)
    }

    /**
     * Step Three
     *
     * - Victor gets Peggy's message from step 2 and PGP-verifies it
     * - Victor recovers data from his saved session and the message from Peggy.
     * - Victor creates a challenge vector of k random bits (k = length of Peggy's commitment lists).
     * - Victor stores his session: new values are the challenge vector and the commitments from Peggy.
     * - Victor pgp-signs and sends a message to Peggy with:
     *      - Session id
     *      - Challenge vector
     */
    fun stepThree(stepTwoMessage: StepTwoMessage): StepThreeMessage {
        require(pgpVerify(stepTwoMessage.pgpSignature, stepTwoMessage.pgpPublicKey, stepTwoMessage.reBlindedVerifierHashes))
        peggyPgpPublicKey = stepTwoMessage.pgpPublicKey
        val sessionId = stepTwoMessage.sessionId
        val session = sessions.first { it.sessionId == sessionId }
        val k = stepTwoMessage.blindedAttesterHashes.size
        val blindFactor = session.blindFactor
        val challenge = session.challenge.toMutableList()
        if (challenge.isEmpty()) {
            challenge.addAll(generateChallengeVector(k))
        }
        val signatureStepThree = pgpSign("$sessionId@#~${Json.encodeToString(challenge)}", pgpPrivateKey)
        val newSession = VictorSession(
            sessionId = sessionId,
            blindFactor = blindFactor,
            blindedVerifiers = session.blindedVerifiers,
            pgpPublicKey = pgpPublicKey, // here in reality we would not save the public key according to the thesis.
            challenge = challenge,
            blindedAttesterHashes = stepTwoMessage.blindedAttesterHashes,
            reBlindedVerifierHashes = stepTwoMessage.reBlindedVerifierHashes,
            message = message
        )
        store(newSession)
        return StepThreeMessage(
            sessionId,
            challenge,
            signatureStepThree
        )
    }

    /**
     * Step Five
     *
     * - Victor gets Peggy's message from step 2 and PGP-verifies it
     * - Victor recovers data from his saved session and the message from Peggy.
     * - Victor initializes a trust integer value with -1
     * - Victor iterates his challenge vector and Peggy's response:
     *      - when vector element is 0, the response element is Peggy's blinding factor for that commitment set.
     *          - Victor uses this blinding factor to reconstruct the set of hashes of re-blinded verifiers.
     *          - Victor asserts this set is equal to the one he got from Peggy.
     *      - when vector element is 1, the response element contains both Peggy's blinded attesters and salt
     *          - Victor iterates Peggy's blinded attesters:
     *              - Victor **fot-verifies** the message with attester's blinded public key and signature
     *              - Victor reconstructs Peggy's commitment sets
     *              (blinded attester hash set and re-blinded verifier hash set) using:
     *                  - Peggy's blinded attesters
     *                  - each Peggy's blinded attester's **fot** public keys as verifiers
     *                  - his own blind factor
     *          - Victor asserts that his reconstructed blinded attester hash set match Peggy's blinded attester hash set
     *          - If trust value is -1 (is still not set), then it is set to the **size of the intersection** of the
     *          reconstructed re-blinded verifier hash set and Peggy's re-blinded verifier hash set.
     *          - If trust value is already set, then assert it is equal to the **size of the intersection** of the
     *          reconstructed re-blinded verifier hash set and Peggy's re-blinded verifier hash set.
     *
     *          Why should the intersection of the reconstructed re-blinded verifier hash set and Peggy's
     *          re-blinded verifier hash set contain Walter's Public key? This is because:
     *              - blinding function is commutative.
     *              - Peggy's blinded attesters' public keys were blinded by Peggy and now are re-blinded by Victor
     *              and we get the **fot hash** of that.
     *              - Victor's blinded verifiers' public keys were blinded by Victor and then they were re-blinded
     *              by Peggy and we got the **fot hash** of that.
     *              - Given that blinding function is commutative, Peggy's and Victor's re-blinded verifier hashes
     *              should be equal. One was blinded by Victor and re-blinded by Peggy, and the other one was
     *              blinded by Peggy and re-blinded by Victor.
     *
     * - The trust value is the trust value of the message and the return of the fot algorithm.
     *
     * - **I saw a catch**: When Victor generates the random bit **challenge vector**,
     * he should try several times until the vector **has at least one bit with value 1**.
     * The reason is that the 0s will not cause the trust value to be set and therefore
     * the return would be -1.
     *
     */
    fun stepFive(stepFourMessage: StepFourMessage): Int {
        require(pgpVerify(stepFourMessage.pgpSignature, peggyPgpPublicKey, stepFourMessage.response))
        val sessionId = stepFourMessage.sessionId
        val session = sessions.first { it.sessionId == sessionId }
        val challenge = session.challenge
        println("challenge: $challenge")
        val response = stepFourMessage.response
        val peggyReblindedVerifierHashes = session.reBlindedVerifierHashes
        val peggyBlindedAttesterHashes = session.blindedAttesterHashes
        val blindedVerifiers = session.blindedVerifiers
        require(challenge.isNotEmpty())
        var trust = -1
        val victorBlindFactor = session.blindFactor
        val k = challenge.size
        repeat(k) { i ->
            if (challenge[i] == 0) {
                val peggyBlindingFactor = (response[i] as BlindingFactor).blindingFactor
                val reblindedVerifierHashSet = mutableSetOf<String>()
                blindedVerifiers.forEach { verifierKey ->
                    reblindedVerifierHashSet.add(fotHash(Json.encodeToString(blindFotPublicKey(verifierKey, peggyBlindingFactor))))
                }
                // VERIFICATION IS DONE WITH RE-BLINDED VERIFIER HASHES WHEN CHALLENGE BIT IS 0
                require(reblindedVerifierHashSet == peggyReblindedVerifierHashes[i])
            } else {
                val (peggyBlindedAttesters, salt) = response[i] as BlindedAttestersAndSalt
                val reblindedVerifierHashSet = mutableSetOf<String>()
                val blindedAttesterHashSet = mutableSetOf<String>()
                peggyBlindedAttesters.forEach { attester ->
                    val (signature, publicKey) = attester
                    // VERIFICATION IS DONE WITH BLINDED SIGNATURE AND PUBLIC KEY WHEN CHALLENGE BIT IS 1
                    require(fotVerify(signature, publicKey, message))
                    blindedAttesterHashSet.add(fotHash("${Json.encodeToString(attester)}@#~$salt"))
                    reblindedVerifierHashSet.add(fotHash(Json.encodeToString(blindFotPublicKey(publicKey, victorBlindFactor))))
                }
                require(blindedAttesterHashSet == peggyBlindedAttesterHashes[i])
                if (trust == -1) {
                    trust = (reblindedVerifierHashSet.intersect(peggyReblindedVerifierHashes[i])).size // assign trust first time
                } else {
                    require(trust == (reblindedVerifierHashSet.intersect(peggyReblindedVerifierHashes[i]).size)) // verify its same trust next times
                }
            }
        }
        return trust
    }

    private fun store(session: VictorSession) {
        sessions.removeIf { it.sessionId == session.sessionId }
        sessions.add(session)
    }
}

data class VictorSession(
    val sessionId: String,
    val blindFactor: Double,
    val blindedVerifiers: Set<FotPublicKey>,
    val pgpPublicKey: PgpPublicKey,
    val challenge: List<Int> = emptyList(),
    val blindedAttesterHashes: List<Set<String>> = emptyList(),
    val reBlindedVerifierHashes: List<Set<String>> = emptyList(),
    val message: Message? = null,
)