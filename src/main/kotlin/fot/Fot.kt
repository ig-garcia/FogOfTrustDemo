package fot

class FotDemo {
    private lateinit var walter: Walter
    private lateinit var peggy: Peggy
    private lateinit var victor: Victor
    private val fotMessages = mutableListOf<Any>()
    private val k = 3
    private val saltLength = 4

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