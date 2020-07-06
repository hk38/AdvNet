package ucl.hk69.advnet

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.util.Base64
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.*
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.DHPublicKeySpec
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

    var btAdapter: BluetoothAdapter? = null

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
        // 相手の公開鍵を生成
        val publicKeySpec = DHPublicKeySpec(othersY, p, g)
        val keyFactory: KeyFactory = KeyFactory.getInstance("DiffieHellman")
        val othersPublicKey: DHPublicKey = keyFactory.generatePublic(publicKeySpec) as DHPublicKey

        // 相手の公開鍵と自分の秘密鍵から共通鍵を生成
        val keyAgreement: KeyAgreement = KeyAgreement.getInstance("DiffieHellman")
        keyAgreement.init(myPrivateKey)
        keyAgreement.doPhase(othersPublicKey, true)
        return keyAgreement.generateSecret("AES")
    }

    fun secKey2StrKey(secKey: SecretKey):String{
        return Base64.encodeToString(secKey.encoded, Base64.DEFAULT)
    }

    fun strKey2SecKey(strKey:String):SecretKey{
        val encodedKey: ByteArray = Base64.decode(strKey, Base64.DEFAULT)
        return SecretKeySpec(encodedKey, 0, encodedKey.size, "AES")
    }

    //            GlobalScope.launch{
    //                val svSoc = BluetoothAdapter.getDefaultAdapter().listenUsingRfcommWithServiceRecord("test", myUUID)
    //                val soc = svSoc.accept()
    //                val dos = DataOutputStream(soc.outputStream)
    //            }
}