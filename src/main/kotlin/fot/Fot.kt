package fot

class FotDemo {
    private lateinit var walter: Walter
    private lateinit var peggy: Peggy
    private lateinit var victor: Victor
    private val fotMessages = mutableListOf<Any>()
    private val k = 3
    private val saltLength = 4

    /**
     * FOT algorithm high-level description
     *
     * - Read step Zero description.
     * - Step One:
     *      - Victor starts the process, generates session id, sends his blinded verifiers to Peggy.
     * - Step Two:
     *      - Peggy generates a vector of blinding factors of size k.
     *      - Peggy generates k commitment pairs:
     *          - Commitment of Peggy's own hashed blinded attesters with "alpha"-long bits salt
     *          - Commitment of Victor's hashed re-blinded verifiers
     *      - Peggy sends commitments to Victor.
     * - Step Three:
     *      - Victor generates a challenge vector of k random bits and sends it to Peggy.
     * - Step Four:
     *      - Peggy generates a response vector of k elements:
     *          - If Victor's challenge vector element is 0, response element is
     *          Peggy's blinding factor for that element.
     *          - If Victor's challenge vector element is 1, response element is
     *          the blinded attester and the salt for that element.
     *      - Peggy sends the response vector to Victor.
     * - Step Five:
     *      - Victor iterates Peggy's response and his challenge vector:
     *      - In each case he reconstructs Peggy's commitments in a different way depending on
     *      the value of current challenge vector element.
     *      - Victor asserts that his reconstructed commitments match Peggy's original commitments.
     *      - Only in the cases when the challenge vector element value is 1, the trust value
     *      (aka the output of the algorithm) is assigned, and in successive 1 values it is checked.
     *
     * - Comments: Observe how the participants (Victor and Peggy) only interact using:
     *      - hashes
     *      - blinding factors
     *      - blinded attesters
     *      - blinded public keys
     *
     *      - This means "zero knowledge proof" (ZKP) is achieved because no sensitive information
     *      is known by other than the owner of such information.
     *      - Observe PGP operations (sign, verify) and keys are used, but just as a means to
     *      protect the communication channel. The real verification has nothing to do with them.
     */
    fun fot(message: Message): Int {
        stepZero(message)
        stepOne()
        stepTwo(fotMessages[0] as StepOneMessage)
        stepThree(fotMessages[1] as StepTwoMessage)
        stepFour(fotMessages[2] as StepThreeMessage)
        val trust = stepFive(fotMessages[3] as StepFourMessage)
        return trust
    }

    /**
     * Step Zero
     *
     * Roles:
     * - Peggy wants to be trusted, so she sends her message (in PGP case a public key certificate) to partners for signing.
     * - Walter **fot signs** Peggy's message, becoming an attester for Peggy's identity in this message.
     * - Victor wants to find trusted verifiers (trusted attesters public keys) to verify the messages they attest.
     *
     *
     * - Victor adds the participants
     * - Peggy sends the message to Walter for signing.
     * - Walter **fot signs** the message and sends the signature and his public key to Peggy.
     * - Walter sends his **fot public key** to Victor: Walter wants to become a trusted verifier.
     */
    fun stepZero(message: Message) { // this is the "Preliminaries" of the thesis.
        walter = Walter()
        peggy = Peggy(message)
        victor = Victor(message, Participants(prover = "Peggy", verifier = "Victor"))
        val stepZeroMessagePeggyToWalter = peggy.stepZeroSendMessageToWalter()
        val stepZeroMessageWalterToPeggy = walter.signMessageAndSendToPeggy(stepZeroMessagePeggyToWalter)
        peggy.stepZeroAddWalterAttester(stepZeroMessageWalterToPeggy)
        val stepZeroMessageWalterToVictor = walter.sendPublicKeyToVictor()
        victor.stepZeroAddWalterVerifier(stepZeroMessageWalterToVictor)
    }

    fun stepOne() {
        val stepOneMessage = victor.stepOne()
        fotMessages.add(stepOneMessage)
    }

    fun stepTwo(stepOneMessage: StepOneMessage) {
        val stepTwoMessage = peggy.stepTwo(stepOneMessage, k, saltLength)
        fotMessages.add(stepTwoMessage)
    }

    fun stepThree(stepTwoMessage: StepTwoMessage) {
        val stepThreeMessage = victor.stepThree(stepTwoMessage)
        fotMessages.add(stepThreeMessage)
    }

    fun stepFour(stepThreeMessage: StepThreeMessage) {
        val stepFourMessage = peggy.stepFour(stepThreeMessage)
        fotMessages.add(stepFourMessage)
    }

    fun stepFive(stepFourMessage: StepFourMessage): Int {
        return victor.stepFive(stepFourMessage)
    }
}



fun main() {
    val message = Message(from = "Peggy", to = "Walter", content = "messageContent")
    val result = FotDemo().fot(message)
    println("fot result: $result")
}