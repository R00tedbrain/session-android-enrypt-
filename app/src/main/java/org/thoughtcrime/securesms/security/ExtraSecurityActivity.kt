package org.thoughtcrime.securesms.security

import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import network.loki.messenger.R

class ExtraSecurityActivity : AppCompatActivity() {

    companion object {
        private const val PREF_FILE_NAME = "encryption_prefs"
        private const val KEY_ENCRYPTION_ENABLED = "encryption_enabled"
        private const val KEY_ALGORITHM = "encryption_algorithm"
        private const val KEY_SELECTED_KEY_ALIAS = "encryption_key_alias"
        private const val KEY_PREFIX = "encryption_key_"  // Prefijo para las claves de cifrado almacenadas
    }

    // Obtenemos el ID de conversación pasado desde ConversationActivityV2
    private val conversationId: String? by lazy {
        intent.getStringExtra("CONVERSATION_ID")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Establecer el diseño de la actividad con los componentes de la interfaz
        setContentView(R.layout.activity_extra_security)

        // Ejemplo de uso del conversationId (puedes adaptarlo según tus necesidades)
        conversationId?.let {
            // Por ejemplo, mostrarlo en un Toast o registrarlo en un log
            // Toast.makeText(this, "Conversation ID: $it", Toast.LENGTH_SHORT).show()
        }

        // Inicializar EncryptedSharedPreferences para almacenar la configuración de forma segura
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        val sharedPreferences = EncryptedSharedPreferences.create(
            this,
            PREF_FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        // Referencias a los componentes de UI en el diseño usando los IDs definidos en el XML
        val switchEncryption = findViewById<Switch>(R.id.switch_enable)
        val spinnerAlgorithm = findViewById<Spinner>(R.id.spinnerAlgorithm)
        val spinnerKey = findViewById<Spinner>(R.id.spinnerKey)

        // Lista de algoritmos de cifrado disponibles
        val algorithms = listOf("AES", "DES", "CAMELLIA", "CHACHA20POLY1305", "XCHACHA20POLY1305")
        val algoAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, algorithms)
        algoAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerAlgorithm.adapter = algoAdapter

        // Obtener todas las entradas almacenadas para buscar claves de cifrado guardadas
        val allPrefs = sharedPreferences.all
        val keyAliasesList = allPrefs.keys
            .filter { it.startsWith(KEY_PREFIX) }
            .map { it.removePrefix(KEY_PREFIX) }
            .toMutableList()

        // Texto placeholder para cuando no hay claves disponibles
        val noKeysPlaceholder = "No hay claves de cifrado"
        if (keyAliasesList.isEmpty()) {
            keyAliasesList.add(noKeysPlaceholder)
        }

        // Adaptador para el spinner de selección de clave
        val keyAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, keyAliasesList)
        keyAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerKey.adapter = keyAdapter

        // Cargar la configuración guardada actualmente
        var encryptionEnabled = sharedPreferences.getBoolean(KEY_ENCRYPTION_ENABLED, false)
        val savedAlgorithm = sharedPreferences.getString(KEY_ALGORITHM, algorithms[0]) ?: algorithms[0]
        val savedKeyAlias = sharedPreferences.getString(KEY_SELECTED_KEY_ALIAS, null)

        // Asegurar consistencia: si estaba activado pero no hay clave disponible, desactivar cifrado
        if (encryptionEnabled && keyAliasesList.size == 1 && keyAliasesList[0] == noKeysPlaceholder) {
            encryptionEnabled = false
            sharedPreferences.edit().putBoolean(KEY_ENCRYPTION_ENABLED, false).apply()
        }

        // Determinar la clave inicialmente seleccionada
        val initialKeyAlias = if (!savedKeyAlias.isNullOrEmpty() && keyAliasesList.contains(savedKeyAlias)) {
            savedKeyAlias  // usar la clave guardada si existe en la lista
        } else {
            if (keyAliasesList.isNotEmpty() && keyAliasesList[0] != noKeysPlaceholder) {
                keyAliasesList[0]
            } else {
                ""
            }
        }

        // Establecer el estado inicial de la interfaz según las preferencias guardadas
        switchEncryption.isChecked = encryptionEnabled
        val algoIndex = algorithms.indexOf(savedAlgorithm)
        if (algoIndex >= 0) {
            spinnerAlgorithm.setSelection(algoIndex)
        }
        if (initialKeyAlias.isNotEmpty()) {
            val keyIndex = keyAliasesList.indexOf(initialKeyAlias)
            if (keyIndex >= 0) {
                spinnerKey.setSelection(keyIndex)
            }
        } else if (keyAliasesList.isNotEmpty() && keyAliasesList[0] == noKeysPlaceholder) {
            spinnerKey.setSelection(0)
        }

        // Habilitar o deshabilitar los spinners según el estado del cifrado
        spinnerAlgorithm.isEnabled = encryptionEnabled
        spinnerKey.isEnabled = encryptionEnabled && keyAliasesList[0] != noKeysPlaceholder

        // Declarar y asignar el listener para el switch usando lateinit para evitar referencias circulares
        lateinit var switchListener: CompoundButton.OnCheckedChangeListener
        switchListener = CompoundButton.OnCheckedChangeListener { _, isChecked ->
            if (isChecked && keyAliasesList[0] == noKeysPlaceholder) {
                Toast.makeText(this, "Por favor, agrega una clave de cifrado primero.", Toast.LENGTH_SHORT).show()
                switchEncryption.setOnCheckedChangeListener(null)
                switchEncryption.isChecked = false
                switchEncryption.setOnCheckedChangeListener(switchListener)
                return@OnCheckedChangeListener
            }
            sharedPreferences.edit().putBoolean(KEY_ENCRYPTION_ENABLED, isChecked).apply()
            spinnerAlgorithm.isEnabled = isChecked
            spinnerKey.isEnabled = isChecked && keyAliasesList[0] != noKeysPlaceholder
        }
        switchEncryption.setOnCheckedChangeListener(switchListener)

        // Listener para cambios en la selección del algoritmo de cifrado
        spinnerAlgorithm.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?, position: Int, id: Long) {
                val selectedAlgo = algorithms[position]
                sharedPreferences.edit().putString(KEY_ALGORITHM, selectedAlgo).apply()
            }
            override fun onNothingSelected(parent: AdapterView<*>) {}
        }

        // Listener para cambios en la selección de la clave de cifrado
        spinnerKey.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: View?, position: Int, id: Long) {
                val alias = keyAliasesList[position]
                if (alias != noKeysPlaceholder) {
                    sharedPreferences.edit().putString(KEY_SELECTED_KEY_ALIAS, alias).apply()
                }
            }
            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
    }
}
