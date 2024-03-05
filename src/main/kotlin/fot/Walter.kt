package fot

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class Walter {
    private val fotPublicKey = FotPublicKey("WalterPublicKey")
    private val fotPrivateKey = FotPrivateKey("WalterPrivateKey")

    fun signMessageAndSendToPeggy(stepZeroMessage: StepZeroMessagePeggyToWalter): StepZeroMessageWalterToPeggy  {
        val messageSignature = fotSign(Json.encodeToString(stepZeroMessage.message), fotPrivateKey)
        val walterAttester = Attester(messageSignature, fotPublicKey)
        return StepZeroMessageWalterToPeggy(walterAttester)
    }

    fun sendPublicKeyToVictor(): StepZeroMessageWalterToVictor {
        return StepZeroMessageWalterToVictor(fotPublicKey)
    }
}