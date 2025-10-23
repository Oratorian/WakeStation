package com.wakestation.android.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.wakestation.android.WakeStationApplication
import com.wakestation.android.databinding.ActivityMainBinding
import com.wakestation.android.ui.viewmodel.LoginViewModel
import com.wakestation.android.ui.viewmodel.LoginViewModelFactory
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var app: WakeStationApplication
    private lateinit var viewModel: LoginViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        app = application as WakeStationApplication
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        initializeViewModel()
        setupViews()
        observeViewModel()

        // Check if user is already logged in
        if (app.authRepository.isLoggedIn()) {
            navigateToDashboard()
        } else {
            // Pre-fill username if saved
            binding.etUsername.setText(app.authRepository.getSavedUsername())
        }
    }

    private fun initializeViewModel() {
        val factory = LoginViewModelFactory(app.authRepository, app.preferenceManager)
        viewModel = ViewModelProvider(this, factory)[LoginViewModel::class.java]
    }

    private fun setupViews() {
        // Set server URL from preferences
        binding.etServerUrl.setText(app.preferenceManager.serverUrl)

        binding.btnLogin.setOnClickListener {
            // Prevent multiple rapid clicks
            if (viewModel.isLoading.value == true) {
                android.util.Log.d("MainActivity", "Login already in progress, ignoring click")
                return@setOnClickListener
            }

            val username = binding.etUsername.text.toString().trim()
            val password = binding.etPassword.text.toString()
            val serverUrl = binding.etServerUrl.text.toString().trim()
            val remember = binding.cbRememberMe.isChecked

            android.util.Log.d("MainActivity", "Login button clicked for user: $username")

            if (validateInput(username, password, serverUrl)) {
                // Update server URL if changed
                if (serverUrl != app.preferenceManager.serverUrl) {
                    android.util.Log.d("MainActivity", "Server URL changed, updating repositories")
                    app.updateServerUrl(serverUrl)
                    initializeViewModel() // Recreate ViewModel with updated repository
                }

                viewModel.login(username, password, remember)
            }
        }

        binding.btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    private fun observeViewModel() {
        viewModel.isLoading.observe(this) { isLoading ->
            binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
            binding.btnLogin.isEnabled = !isLoading
        }

        viewModel.loginResult.observe(this) { result ->
            android.util.Log.d("MainActivity", "Login result received: $result")
            android.util.Log.d("MainActivity", "Result success: ${result.isSuccess}")
            result.onSuccess { message ->
                android.util.Log.d("MainActivity", "Login success: $message")
                Toast.makeText(this, "Login successful", Toast.LENGTH_SHORT).show()
                navigateToDashboard()
            }.onFailure { error ->
                android.util.Log.d("MainActivity", "Login failure: ${error.message}")
                Toast.makeText(this, "Login failed: ${error.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun validateInput(username: String, password: String, serverUrl: String): Boolean {
        if (username.isEmpty()) {
            binding.etUsername.error = "Username is required"
            return false
        }

        if (password.isEmpty()) {
            binding.etPassword.error = "Password is required"
            return false
        }

        if (serverUrl.isEmpty()) {
            binding.etServerUrl.error = "Server URL is required"
            return false
        }

        if (!serverUrl.startsWith("http://") && !serverUrl.startsWith("https://")) {
            binding.etServerUrl.error = "Server URL must start with http:// or https://"
            return false
        }

        return true
    }

    private fun navigateToDashboard() {
        val intent = Intent(this, DashboardActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}