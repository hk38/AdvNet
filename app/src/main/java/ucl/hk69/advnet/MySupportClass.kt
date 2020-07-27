package ucl.hk69.advnet

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.DHPublicKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class MySupportClass {
    val MY_UUID = UUID.fromString("5E7B99D0-F404-4425-8125-98A2265B4333")
    val PORT = 55913
    val KAIGI_ON = 1
    val KAIGI_OFF = 2
    val STATE_RED = 3
    val STATE_YELLOW = 4
    val STATE_GREEN = 5
    val STATE_OFF = 6

    fun genKeyPair(): KeyPair {
        val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman")
        keyGen.initialize(2048)
        return keyGen.generateKeyPair()
    }

    fun makeKeyPair(p: BigInteger, g: BigInteger): KeyPair {
        val paramSpec = DHParameterSpec(p, g)
        val keyGen = KeyPairGenerator.getInstance("DiffieHellman")
        keyGen.initialize(paramSpec)
        return keyGen.generateKeyPair()
    }

    fun genSecKey(p: BigInteger, g: BigInteger, othersY: BigInteger, myPrivateKey: DHPrivateKey): SecretKey {
        val publicKeySpec = DHPublicKeySpec(othersY, p, g)
        val keyFactory: KeyFactory = KeyFactory.getInstance("DiffieHellman")
        val othersPublicKey: DHPublicKey = keyFactory.generatePublic(publicKeySpec) as DHPublicKey

        val keyAgreement: KeyAgreement = KeyAgreement.getInstance("DiffieHellman")
        keyAgreement.init(myPrivateKey)
        keyAgreement.doPhase(othersPublicKey, true)
        return keyAgreement.generateSecret("AES")
    }

    fun secKey2StrKey(secKey: SecretKey):String{
        return Base64.getEncoder().encodeToString(secKey.encoded)
    }

    fun strKey2SecKey(strKey:String?):SecretKey{
        val encodedKey: ByteArray = Base64.getDecoder().decode(strKey)
        return SecretKeySpec(encodedKey, 0, encodedKey.size, "AES")
    }


    fun enc(plainText: Int, key: SecretKey, iv: IvParameterSpec): String {
        val encrypter = Cipher.getInstance("AES/CBC/PKCS5Padding")
        encrypter.init(Cipher.ENCRYPT_MODE, key, iv)

        val mac = Mac.getInstance("HmacSHA256");
        mac.init(key)

        val msgArray = encrypter.doFinal(plainText.toString().toByteArray())
        val macArray = mac.doFinal(msgArray)

        val cryptArray = ByteArray(msgArray.size + macArray.size)
        System.arraycopy(macArray, 0, cryptArray, 0, macArray.size)
        System.arraycopy(msgArray, 0, cryptArray, macArray.size, msgArray.size)

        return Base64.getEncoder().encodeToString(cryptArray)
    }

    fun dec(cryptText: String, key: SecretKey, iv: IvParameterSpec): Int {
        val cryptArray =  Base64.getDecoder().decode(cryptText)
        val macArray = cryptArray.sliceArray(0..31)
        val msgArray = cryptArray.sliceArray(32 until cryptArray.size)

        val mac = Mac.getInstance("HmacSHA256");
        mac.init(key)
        if(!macArray.contentEquals(mac.doFinal(msgArray))) return 0

        val decrypter = Cipher.getInstance("AES/CBC/PKCS5Padding")
        decrypter.init(Cipher.DECRYPT_MODE, key, iv)
        return String(decrypter.doFinal(msgArray)).toInt()
    }
}