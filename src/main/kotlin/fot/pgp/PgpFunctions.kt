package fot.pgp

import fot.PgpKeyPair
import fot.PgpPrivateKey
import fot.PgpPublicKey
import fot.PgpSignature
import org.pgpainless.sop.SOPImpl
import sop.enums.InlineSignAs


private val sop = SOPImpl()

fun pgpSignature(input: String, pgpPrivateKey: PgpPrivateKey): PgpSignature {
    val signature = sop.detachedSign()
        .key(pgpPrivateKey.key.byteInputStream())
        .data(input.byteInputStream())
        .toByteArrayAndResult().bytes
    return PgpSignature(signature.decodeToString())
}

fun pgp_Sign(input: String, pgpPrivateKey: PgpPrivateKey): String {
    return sop.inlineSign()
        .mode(InlineSignAs.text) // or 'Binary'
        .key(pgpPrivateKey.key.byteInputStream())
        .data(input.byteInputStream())
        .bytes
        .decodeToString()
}

fun pgpEncryptAndSign(input: String, recipientPgpPublicKey: PgpPublicKey, ownPrivateKey: PgpPrivateKey): String {
    return sop.encrypt()
        .withCert(recipientPgpPublicKey.key.byteInputStream())
        .signWith(ownPrivateKey.key.byteInputStream())
        .plaintext(input.byteInputStream())
        .bytes
        .decodeToString()
}

fun pgpDecryptAndVerify(input: String, ownPgpPrivateKey: PgpPrivateKey, senderPgpPublicKey: PgpPublicKey): String {
    return sop.decrypt()
        .withKey(ownPgpPrivateKey.key.byteInputStream())
        .verifyWithCert(senderPgpPublicKey.key.byteInputStream())
        .ciphertext(input.byteInputStream())
        .toByteArrayAndResult()
        .bytes
        .decodeToString()
}

fun pgpVerify(signedMessage: String, publicKey: PgpPublicKey): ByteArray {
    return sop.inlineVerify()
        .cert(publicKey.key.byteInputStream())
        .data(signedMessage.byteInputStream()).toByteArrayAndResult()
        .bytes
}

fun generateKeyPair(userId: String): PgpKeyPair {
    println("generating keypair for $userId...")
    val keyBytes = sop.generateKey()
        .userId(userId)
        .generate()
        .bytes
    val privateKey = PgpPrivateKey(keyBytes.decodeToString())
    val certificate = sop.extractCert()
        .key(keyBytes)
        .bytes
    val publicKey = PgpPublicKey(certificate.decodeToString())
    println("done generating keypair for $userId.")
    return PgpKeyPair(privateKey, publicKey)
}