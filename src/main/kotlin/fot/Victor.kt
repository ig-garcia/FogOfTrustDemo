package fot

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


    fun stepOne(): StepOneMessage {
        val blindFactor = blindFactGen()
        val blindedVerifiers = mutableSetOf<FotPublicKey>()
        trustedVerifiers.forEach { pk ->
            blindedVerifiers.add(blindFotPublicKey(pk, blindFactor))
        }
        val sessionId = (Json.encodeToString(participants) + Json.encodeToString(message)).hashCode().toString()
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

    fun stepThree(stepTwoMessage: StepTwoMessage): StepThreeMessage {
        assert(pgpVerify(stepTwoMessage.pgpSignature, stepTwoMessage.pgpPublicKey, stepTwoMessage.reBlindedVerifierHashes))
        peggyPgpPublicKey = stepTwoMessage.pgpPublicKey
        val sessionId = stepTwoMessage.sessionId
        val session = sessions.first { it.sessionId == stepTwoMessage.sessionId }
        val k = stepTwoMessage.blindedAttesterHashes.size
        val blindFactor = session.blindFactor
        val challenge = session.challenge.toMutableList()
        if (challenge.isEmpty()) {
            repeat(k) {
                challenge.add(randomBit())
            }
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

    fun stepFive(stepFourMessage: StepFourMessage): Set<String> {
        assert(pgpVerify(stepFourMessage.pgpSignature, peggyPgpPublicKey, stepFourMessage.response))
        val sessionId = stepFourMessage.sessionId
        val session = sessions.first { it.sessionId == sessionId }
        val challenge = session.challenge
        val response = stepFourMessage.response
        val peggyReblindedVerifierHashes = session.reBlindedVerifierHashes
        val peggyBlindedAttesterHashes = session.blindedAttesterHashes
        assert(challenge.isNotEmpty())
        var trust: Set<String> = setOf("-1")
        val victorBlindFactor = session.blindFactor
        val k = challenge.size
        repeat(k) { i ->
            if (challenge[i] == 0) {
                val peggyBlindingFactor = response[i] as Double
                val reblindedVerifierPkHashes = mutableSetOf<String>()
                trustedVerifiers.forEach { verifierKey ->
                    reblindedVerifierPkHashes.add(fotHash(blindFotPublicKey(verifierKey, peggyBlindingFactor)))
                }
                // VERIFICATION IS DONE WITH REBLINDED VERIFIER HASHES WHEN CHALLENGE BIT IS 0
                assert(reblindedVerifierPkHashes == peggyReblindedVerifierHashes[i])
            } else {
                val (peggyBlindedAttesters, salt) = response[i] as BlindedAttestersAndSalt
                val reblindedAttesterHashes = mutableSetOf<String>()
                val blindedAttesterHashes = mutableSetOf<String>()
                peggyBlindedAttesters.forEach { attester ->
                    val (signature, publicKey) = attester
                    // VERIFICATION IS DONE WITH BLINDED SIGNATURE AND PUBLIC KEY WHEN CHALLENGE BIT IS 1
                    assert(fotVerify(signature, publicKey, message))
                    blindedAttesterHashes.add(fotHash("${Json.encodeToString(attester)}@#~$salt"))
                    reblindedAttesterHashes.add(fotHash(blindFotPublicKey(publicKey, victorBlindFactor)))
                }
                assert(blindedAttesterHashes == peggyBlindedAttesterHashes)
                if (trust == setOf("-1")) {
                    trust = reblindedAttesterHashes.intersect(peggyReblindedVerifierHashes[i]) // assign trust first time
                } else {
                    assert(trust == reblindedAttesterHashes.intersect(peggyReblindedVerifierHashes[i])) // verify its same trust next times
                }
            }
        }
        return trust
    }

    private fun store(session: VictorSession) {
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