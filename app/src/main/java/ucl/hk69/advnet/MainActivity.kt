package ucl.hk69.advnet

import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.Executor
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {
    private val mySup = MySupportClass()
    private val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
    private val masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec)
    private var socket: Socket? = null
    private var dos:DataOutputStream? = null
    private var secNo = 0

    private val pref:SharedPreferences by lazy {
        EncryptedSharedPreferences.create("Data", masterKeyAlias, applicationContext, EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(code: Int, str: CharSequence) {
                    super.onAuthenticationError(code, str)
                    Toast.makeText(applicationContext, "認証エラー: $str", Toast.LENGTH_SHORT).show()
                    finish()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "認証失敗", Toast.LENGTH_SHORT).show()
                    finish()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("生体認証")
            .setSubtitle("生体情報を用いてユーザ認証を行ってください")
            .setNegativeButtonText("キャンセル")
            .build()

        biometricPrompt.authenticate(promptInfo)


        val editor = pref.edit()
        var kaigityu = false

        buttonConnect.setOnClickListener {
            val btManager =
                applicationContext.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            val btAdapter = btManager.adapter
            val btDevices = btAdapter.bondedDevices.toList()
            var btSoc: BluetoothSocket? = null
            for (device in btDevices) {
                if (device.name == "RPI3") btSoc = device.createRfcommSocketToServiceRecord(mySup.MY_UUID)
            }

            if(btSoc == null) {
                return@setOnClickListener
            }

            try {
                btSoc.connect()
                val btDis = DataInputStream(btSoc.inputStream)
                val btDos = DataOutputStream(btSoc.outputStream)

                val keyPair = mySup.genKeyPair()
                val pubKey = keyPair.public as DHPublicKey
                val paramSpec = pubKey.params
                val p = paramSpec.p
                val g = paramSpec.g

                val privKey = keyPair.private as DHPrivateKey
                val y = pubKey.y

                btDos.writeUTF(p.toString())
                btDos.writeUTF(g.toString())
                btDos.writeUTF(y.toString())
                btDos.flush()
                val othersY = btDis.readUTF().toBigInteger()
                val ip = btDis.readUTF()

                val secKey = mySup.genSecKey(p, g, othersY, privKey)

                editor.putString("key", mySup.secKey2StrKey(secKey))
                editor.putString("ip", ip)
                editor.apply()

                if (btSoc.isConnected) {
                    try {
                        btDis.close()
                        btDos.close()
                        btSoc.close()
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                }
                GlobalScope.launch {
                    dos = checkData()
                }
            }catch (e:Exception){
                dos?.close()
                dos = null
                socket?.close()
                socket = null
                e.printStackTrace()
            }
        }

        buttonKaigi.setOnClickListener {
            if (kaigityu) {
                buttonKaigi.setBackgroundResource(R.drawable.shape_rounded_clear)
                buttonKaigi.setTextColor(getColor(R.color.true_black))
            } else {
                buttonKaigi.setBackgroundResource(R.drawable.shape_rounded_red)
                buttonKaigi.setTextColor(getColor(R.color.white))
            }

            GlobalScope.launch {
                val result = if(kaigityu) sendData(mySup.KAIGI_OFF)
                else sendData(mySup.KAIGI_ON)

                if(result == 0) kaigityu = !kaigityu
            }
        }

        buttonStateSyoto.setOnClickListener {
            GlobalScope.launch {
                sendData(mySup.STATE_OFF)
            }
        }

        buttonStateRed.setOnClickListener {
            GlobalScope.launch {
                sendData(mySup.STATE_RED)
            }
        }

        buttonStateYellow.setOnClickListener{
            GlobalScope.launch {
                sendData(mySup.STATE_YELLOW)
            }
        }

        buttonStateGreen.setOnClickListener {
            GlobalScope.launch {
                sendData(mySup.STATE_GREEN)
            }
        }
    }

    private fun sendData(data:Int):Int{
        try {
            if (dos == null) dos = checkData()

            secNo++
            val random = SecureRandom()
            val iv = ByteArray(16)
            random.nextBytes(iv)
            val ivParamSpec = IvParameterSpec(iv)
            dos?.writeUTF(Base64.encodeToString(iv, Base64.DEFAULT))
            dos?.writeUTF(mySup.enc((secNo*10+data), mySup.strKey2SecKey(pref.getString("key", null)), ivParamSpec))
            dos?.flush()

            return if(dos == null) 1
            else 0
        }catch (e:Exception){
            e.printStackTrace()
            return 1
        }
    }

    private fun checkData():DataOutputStream?{
        val ip = pref.getString("ip", null)
        return if(pref.getString("key", null) != null && ip != null) {
            socket = Socket(ip, mySup.PORT)
            DataOutputStream(socket!!.getOutputStream())
        }else null
    }
}