package fot

import kotlin.random.Random

fun blindFactGen(): Double = Random.nextDouble()

fun fotHash(what: Any): String {
    return what.hashCode().toString()
}

fun fotSign(input: String, fotPrivateKey: FotPrivateKey): FotSignature {
    return FotSignature("$fotPrivateKey@#~$input")
}

fun fotVerify(fotSignature: FotSignature, fotPublicKey: FotPublicKey, content: Any): Boolean {
    return true
}

fun blindFotPublicKey(fotPublicKey: FotPublicKey, blindFactor: Double): FotPublicKey {
    return FotPublicKey(fotPublicKey.key, fotPublicKey.blindFactor + blindFactor)
}

fun blindFotSignature(fotSignature: FotSignature, blindFactor: Double): FotSignature {
    return FotSignature(fotSignature.signature, fotSignature.blindFactor + blindFactor)
}

fun blindAttester(attester: Attester, blindFactor: Double): Attester {
    return Attester(blindFotSignature(attester.fotSignature, blindFactor), blindFotPublicKey(attester.fotPublicKey, blindFactor))
}
