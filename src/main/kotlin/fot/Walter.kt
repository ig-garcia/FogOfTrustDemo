package fot

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class Walter(
    email: String = "walter@fot.demo"
) {
    private val fotPublicKey = FotPublicKey("${email}PublicKey")
    private val fotPrivateKey = FotPrivateKey("${email}PrivateKey")

    fun signMessageAndSendToPeggy(stepZeroMessage: StepZeroMessagePeggyToWalter): StepZeroMessageWalterToPeggy  {
        val messageSignature = fotSign(Json.encodeToString(stepZeroMessage.message), fotPrivateKey)
        val walterAttester = Attester(messageSignature, fotPublicKey)
        return StepZeroMessageWalterToPeggy(walterAttester)
    }

    fun sendPublicKeyToVictor(): StepZeroMessageWalterToVictor {
        return StepZeroMessageWalterToVictor(fotPublicKey)
    }
}