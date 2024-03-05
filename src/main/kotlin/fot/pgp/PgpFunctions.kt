package fot.pgp

import fot.PgpPrivateKey
import fot.PgpPublicKey
import fot.PgpSignature

fun pgpSign(input: String, pgpPrivateKey: PgpPrivateKey): PgpSignature {
    return PgpSignature("$pgpPrivateKey@#~$input")
}

fun pgpVerify(pgpSignature: PgpSignature, pgpPublicKey: PgpPublicKey, content: Any): Boolean {
    return true
}