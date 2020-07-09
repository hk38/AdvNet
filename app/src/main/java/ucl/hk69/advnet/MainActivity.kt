package ucl.hk69.advnet

import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.SharedPreferences
import android.graphics.Color
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.google.android.material.snackbar.Snackbar
import kotlinx.android.synthetic.main.activity_main.*
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
    private val ip = "192.168.1.100"
    private var socket: Socket? = null
    private var dos:DataOutputStream? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val preferences = EncryptedSharedPreferences.create("Data", masterKeyAlias, applicationContext, EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV, EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
        val editor = preferences.edit()
        val stateArray = arrayOf(getString(R.string.state_syoto), getString(R.string.state_nono), getString(R.string.state_yesno), getString(R.string.state_yesyes))
        var kaigityu = false

        dos = checkData(preferences)

        buttonConnect.setOnClickListener {
            try {
                val btManager =
                    applicationContext.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
                val btAdapter = btManager.adapter
                val btDevices = btAdapter.bondedDevices.toList()
                val btDeviceNames = mutableListOf<String>()
                for(device in btDevices){
                    btDeviceNames.add(device.name)
                }
                var btSoc: BluetoothSocket? = null

                AlertDialog.Builder(this) // FragmentではActivityを取得して生成
                    .setTitle(getString(R.string.dialog_title_btdevice))
                    .setSingleChoiceItems(btDeviceNames.toTypedArray(), -1) { _, which ->
                        btSoc = btDevices[which].createRfcommSocketToServiceRecord(mySup.MY_UUID)
                    }
                    .setPositiveButton("OK") { _, _ ->
                        if (btSoc != null) {
                            btSoc!!.connect()
                            val btDis = DataInputStream(btSoc!!.inputStream)
                            val btDos = DataOutputStream(btSoc!!.outputStream)

                            val p = btDis.readUTF().toBigInteger()
                            val g = btDis.readUTF().toBigInteger()
                            val othersY = btDis.readUTF().toBigInteger()

                            val keyPair = mySup.makeKeyPair(p, g)
                            val privKey = keyPair.private as DHPrivateKey
                            val pubKey = keyPair.public as DHPublicKey
                            val y = pubKey.y

                            btDos.writeUTF(y.toString())

                            val secKey = mySup.genSecKey(p, g, othersY, privKey)

                            editor.putString("key", mySup.secKey2StrKey(secKey))
                            editor.apply()

                            if(btSoc!!.isConnected) {
                                btDis.close()
                                btDos.close()
                                btSoc?.close()
                            }
                            dos = checkData(preferences)
                        }
                    }
                    .setNegativeButton("Cancel") { _, _ -> }
                    .show()
            }catch (e:Exception){
                Snackbar.make(it, "Error", Snackbar.LENGTH_SHORT).show()
                e.printStackTrace()
            }
        }

        buttonKaigi.setOnClickListener {
            if(dos != null) {
                if (kaigityu) {
                    buttonKaigi.setBackgroundResource(R.drawable.shape_rounded_clear)
                    buttonKaigi.setTextColor(getColor(R.color.true_black))
                    dos!!.writeByte(mySup.KAIGI_OFF)
                } else {
                    buttonKaigi.setBackgroundResource(R.drawable.shape_rounded_red)
                    buttonKaigi.setTextColor(getColor(R.color.white))
                    dos!!.writeByte(mySup.KAIGI_ON)
                }
                kaigityu = !kaigityu
            }else Snackbar.make(it, "通信できませんでした", Snackbar.LENGTH_SHORT).show()
        }

        buttonState.setOnClickListener {
            if(dos != null) {
                AlertDialog.Builder(this) // FragmentではActivityを取得して生成
                    .setTitle(getString(R.string.dialog_title_state))
                    .setItems(stateArray) { _, which ->
                        when (which) {
                            0 -> {
                                setBottunSyoto()
                                dos!!.writeByte(mySup.STATE_OFF)
                            }
                            1 -> {
                                setButtonNoNo()
                                dos!!.writeByte(mySup.STATE_RED)
                            }
                            2 -> {
                                setButtonYesNo()
                                dos!!.writeByte(mySup.STATE_YELLOW)
                            }
                            3 -> {
                                setButtonYesYes()
                                dos!!.writeByte(mySup.STATE_GREEN)
                            }
                        }
                    }.show()
            }else Snackbar.make(it, "通信できませんでした", Snackbar.LENGTH_SHORT).show()
        }
    }

    override fun onDestroy() {
        if(socket?.isConnected!!){
            if (!socket?.isOutputShutdown!!) {
                dos?.writeByte(mySup.DISCONNECT)
                dos?.close()
            }
            socket?.close()
        }
        super.onDestroy()
    }

    private fun setBottunSyoto(){
        buttonState.text = getString(R.string.state_syoto)
        buttonState.setBackgroundResource(R.drawable.shape_rounded_black)
        buttonState.setTextColor(getColor(R.color.white))
    }

    private fun setButtonNoNo(){
        buttonState.text = getString(R.string.state_nono)
        buttonState.setBackgroundResource(R.drawable.shape_rounded_red)
        buttonState.setTextColor(getColor(R.color.white))
    }

    private fun setButtonYesNo(){
        buttonState.text = getString(R.string.state_yesno)
        buttonState.setBackgroundResource(R.drawable.shape_rounded_yellow)
        buttonState.setTextColor(getColor(R.color.black))
    }

    private fun setButtonYesYes(){
        buttonState.text = getString(R.string.state_yesyes)
        buttonState.setBackgroundResource(R.drawable.shape_rounded_green)
        buttonState.setTextColor(getColor(R.color.white))
    }

    private fun checkData(pref:SharedPreferences):DataOutputStream?{
        return if((pref.getString("key", null) == null)) {
            buttonConnect.setTextColor(Color.RED)
            textKeyState.text = getString(R.string.not_have_key)
            null
        }else {
            buttonConnect.setTextColor(Color.GRAY)
            textKeyState.text = getString(R.string.have_key)

            socket = Socket(ip, mySup.PORT)
            DataOutputStream(socket!!.getOutputStream())
        }
    }
}