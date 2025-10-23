package com.wakestation.android.ui

import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.wakestation.android.WakeStationApplication
import com.wakestation.android.databinding.ActivitySettingsBinding
import com.wakestation.android.utils.BiometricHelper
import com.wakestation.android.utils.PreferenceManager

class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private lateinit var preferenceManager: PreferenceManager
    private lateinit var biometricHelper: BiometricHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        preferenceManager = (application as WakeStationApplication).preferenceManager
        biometricHelper = BiometricHelper(this)

        setupToolbar()
        setupShutdownCredentials()
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.apply {
            title = "Settings"
            setDisplayHomeAsUpEnabled(true)
        }
    }

    private fun setupShutdownCredentials() {
        updateShutdownCredentialsStatus()

        // Handle set credentials button
        binding.btnSetShutdownCredentials.setOnClickListener {
            showSecureCredentialDialog()
        }

        // Handle clear button
        binding.btnClearShutdownCredentials.setOnClickListener {
            showClearCredentialsDialog()
        }
    }

    private fun updateShutdownCredentialsStatus() {
        val hasCredentials = preferenceManager.saveShutdownCredentials &&
                preferenceManager.shutdownUsername.isNotEmpty()

        if (hasCredentials) {
            binding.tvShutdownCredentialsStatus.text =
                "Credentials saved for user: ${preferenceManager.shutdownUsername}"
            binding.btnSetShutdownCredentials.text = "Update Shutdown Credentials"
            binding.btnClearShutdownCredentials.visibility = View.VISIBLE
        } else {
            binding.tvShutdownCredentialsStatus.text = "No shutdown credentials saved"
            binding.btnSetShutdownCredentials.text = "Set Shutdown Credentials"
            binding.btnClearShutdownCredentials.visibility = View.GONE
        }
    }

    private fun showSecureCredentialDialog() {
        if (!biometricHelper.isBiometricAvailable()) {
            Toast.makeText(this, "Biometric authentication not available on this device", Toast.LENGTH_LONG).show()
            return
        }

        biometricHelper.authenticateWithBiometric(
            title = "Set Shutdown Credentials",
            subtitle = "Authenticate to securely save shutdown credentials",
            onSuccess = {
                showCredentialInputDialog()
            },
            onError = { error ->
                Toast.makeText(this, "Authentication failed: $error", Toast.LENGTH_SHORT).show()
            }
        )
    }

    private fun showCredentialInputDialog() {
        // Create secure input dialog
        val linearLayout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 50, 50, 50)
        }

        val usernameInput = android.widget.EditText(this).apply {
            hint = "Username"
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setText(preferenceManager.shutdownUsername) // Pre-fill if updating
        }

        val passwordInput = android.widget.EditText(this).apply {
            hint = "Password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        linearLayout.addView(usernameInput)
        linearLayout.addView(passwordInput)

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Set Shutdown Credentials")
            .setMessage("These credentials will be securely saved and protected by biometric authentication.")
            .setView(linearLayout)
            .setPositiveButton("Save") { _, _ ->
                val username = usernameInput.text.toString().trim()
                val password = passwordInput.text.toString()

                if (username.isEmpty()) {
                    Toast.makeText(this, "Username is required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                if (password.isEmpty()) {
                    Toast.makeText(this, "Password is required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                // Save credentials securely
                preferenceManager.shutdownUsername = username
                preferenceManager.shutdownPassword = password
                preferenceManager.saveShutdownCredentials = true

                updateShutdownCredentialsStatus()
                Toast.makeText(this, "Shutdown credentials saved securely", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showClearCredentialsDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Clear Shutdown Credentials")
            .setMessage("Are you sure you want to remove saved shutdown credentials?")
            .setPositiveButton("Clear") { _, _ ->
                biometricHelper.authenticateWithBiometric(
                    title = "Clear Credentials",
                    subtitle = "Authenticate to remove saved shutdown credentials",
                    onSuccess = {
                        preferenceManager.clearShutdownCredentials()
                        updateShutdownCredentialsStatus()
                        Toast.makeText(this, "Shutdown credentials cleared", Toast.LENGTH_SHORT).show()
                    },
                    onError = { error ->
                        Toast.makeText(this, "Authentication failed: $error", Toast.LENGTH_SHORT).show()
                    }
                )
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                finish()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}