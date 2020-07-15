package ucl.hk69.advnet

import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.SharedPreferences
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.google.android.material.snackbar.Snackbar
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.DataInputStream
import java.io.DataOutputStream
import java.lang.Exception
import java.net.Socket
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey

class MainActivity : AppCompatActivity() {
    private val mySup = MySupportClass()
    private val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
    private val masterKeyAlias = MasterKeys.getOrCreate(keyGenParameterSpec)
    private val ip = "192.168.1.25"
    private var socket: Socket? = null
    private var dos:DataOutputStream? = null
    private var dis:DataInputStream? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val preferences = EncryptedSharedPreferences.create("Data", masterKeyAlias, applicationContext, EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
        val editor = preferences.edit()
        var kaigityu = false

        buttonConnect.setOnClickListener {
            val keyPair = mySup.genKeyPair()
            val pubKey = keyPair.public as DHPublicKey
            val paramSpec = pubKey.params
            val p = paramSpec.p
            val g = paramSpec.g

            val privKey = keyPair.private as DHPrivateKey
            val y = pubKey.y
            Log.d("dh", "鍵準備")

            val btManager =
                applicationContext.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            val btAdapter = btManager.adapter
            val btDevices = btAdapter.bondedDevices.toList()
            var btSoc: BluetoothSocket? = null
            for (device in btDevices) {
                Log.d("device name", device.name)
                if (device.name == "RPI3") btSoc = device.createRfcommSocketToServiceRecord(mySup.MY_UUID)
            }

            if(btSoc == null) {
                Log.d("connect error", "RPI3が見つからなかった")
                return@setOnClickListener
            }

            try {
                btSoc.connect()
                val btDis = DataInputStream(btSoc.inputStream)
                val btDos = DataOutputStream(btSoc.outputStream)
                Log.d("bluetooth", "接続")

                btDos.writeUTF(p.toString())
                btDos.writeUTF(g.toString())
                btDos.writeUTF(y.toString())
                Log.d("make secKey", "鍵要素送信&受信待機")
                val othersY = btDis.readUTF().toBigInteger()

                val secKey = mySup.genSecKey(p, g, othersY, privKey)
                Log.d("dh", "鍵生成")

                editor.putString("key", mySup.secKey2StrKey(secKey))
                editor.apply()
                Log.d("dh", "鍵保存")

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
                    dos = checkData(preferences)
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
                if(dos == null) dos = checkData(preferences)
                if(kaigityu) sendData(mySup.KAIGI_OFF)
                else sendData(mySup.KAIGI_ON)

                kaigityu = !kaigityu
            }
        }

        buttonStateSyoto.setOnClickListener {
            if(dos == null) dos = checkData(preferences)
            GlobalScope.launch {
                sendData(mySup.STATE_OFF)
            }
        }

        buttonStateRed.setOnClickListener {
            GlobalScope.launch {
                if(dos == null) dos = checkData(preferences)
                sendData(mySup.STATE_RED)
            }
        }

        buttonStateYellow.setOnClickListener{
            GlobalScope.launch {
                if(dos == null) dos = checkData(preferences)
                sendData(mySup.STATE_YELLOW)
            }
        }

        buttonStateGreen.setOnClickListener {
            GlobalScope.launch {
                if(dos == null) dos = checkData(preferences)
                sendData(mySup.STATE_GREEN)
            }
        }
    }

    private fun sendData(data:Int){
        try {
            if (dos == null) dos = DataOutputStream(Socket(ip, mySup.PORT).getOutputStream())
            dos!!.writeByte(data)
        }catch (e:Exception){e.printStackTrace()}
    }

    private fun checkData(pref:SharedPreferences):DataOutputStream?{
        return if((pref.getString("key", null) == null)) null
        else {
            socket = Socket(ip, mySup.PORT)
            DataOutputStream(socket!!.getOutputStream())
        }
    }
}