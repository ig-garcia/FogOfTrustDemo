package fot

private val message = Message(from = "Peggy", to = "Walter", content = "messageContent")


class FotDemo {
    private lateinit var walter: Walter
    private lateinit var peggy: Peggy
    private lateinit var victor: Victor
    private val fotMessages = mutableListOf<Any>()
    private val k = 3
    private val saltLength = 4

    fun fot(): Set<String> {
        stepZero()
        stepOne()
        stepTwo(fotMessages[0] as StepOneMessage)
        stepThree(fotMessages[1] as StepTwoMessage)
        stepFour(fotMessages[2] as StepThreeMessage)
        val trust = stepFive(fotMessages[3] as StepFourMessage)
        return trust
    }

    fun stepZero() { // this is the "Preliminaries" of the thesis.
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

    fun stepFive(stepFourMessage: StepFourMessage): Set<String> {
        return victor.stepFive(stepFourMessage)
    }
}



fun main() {

}