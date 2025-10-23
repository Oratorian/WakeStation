package com.wakestation.android.ui

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.wakestation.android.R
import com.wakestation.android.WakeStationApplication
import com.wakestation.android.databinding.ActivityDashboardBinding
import com.wakestation.android.ui.adapter.PCAdapter
import com.wakestation.android.ui.viewmodel.DashboardViewModel
import com.wakestation.android.ui.viewmodel.DashboardViewModelFactory
import com.wakestation.android.utils.BiometricHelper
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class DashboardActivity : AppCompatActivity(), SwipeRefreshLayout.OnRefreshListener {

    private lateinit var binding: ActivityDashboardBinding
    private lateinit var app: WakeStationApplication
    private lateinit var pcAdapter: PCAdapter
    private lateinit var biometricHelper: BiometricHelper

    private val viewModel: DashboardViewModel by viewModels {
        DashboardViewModelFactory(app.pcRepository, app.authRepository)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Enable edge-to-edge display
        WindowCompat.setDecorFitsSystemWindows(window, false)

        app = application as WakeStationApplication
        binding = ActivityDashboardBinding.inflate(layoutInflater)
        setContentView(binding.root)

        biometricHelper = BiometricHelper(this)

        setupWindowInsets()
        setupToolbar()
        setupRecyclerView()
        setupViews()
        observeViewModel()

        // Load PCs with a small delay to ensure session is fully established
        lifecycleScope.launch {
            delay(200) // Brief delay to ensure login session is propagated
            viewModel.loadPCs()
        }
    }

    private fun setupWindowInsets() {
        // Handle system bars (status bar and navigation bar) insets
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())

            // Apply bottom padding to FAB for navigation bar
            val fabParams = binding.fabAddPc.layoutParams as androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams
            fabParams.bottomMargin = 16.dpToPx() + insets.bottom
            binding.fabAddPc.layoutParams = fabParams

            // Apply bottom padding to RecyclerView for navigation bar
            binding.recyclerView.setPadding(
                binding.recyclerView.paddingLeft,
                binding.recyclerView.paddingTop,
                binding.recyclerView.paddingRight,
                88.dpToPx() + insets.bottom
            )

            windowInsets
        }
    }

    private fun Int.dpToPx(): Int {
        return (this * resources.displayMetrics.density).toInt()
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.title = "WakeStation Dashboard"
    }

    private fun setupRecyclerView() {
        pcAdapter = PCAdapter(
            onWakeClick = { pc -> viewModel.wakePC(pc.mac) },
            onShutdownClick = { pc -> showShutdownDialog(pc) },
            onDeleteClick = { pc -> showDeleteDialog(pc) }
        )

        binding.recyclerView.apply {
            layoutManager = LinearLayoutManager(this@DashboardActivity)
            adapter = pcAdapter
        }
    }

    private fun setupViews() {
        binding.swipeRefresh.setOnRefreshListener(this)

        binding.fabAddPc.setOnClickListener {
            startActivity(Intent(this, AddPCActivity::class.java))
        }
    }

    private fun observeViewModel() {
        viewModel.isLoading.observe(this) { isLoading ->
            if (!binding.swipeRefresh.isRefreshing) {
                binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
            }
        }

        viewModel.pcs.observe(this) { pcs ->
            binding.swipeRefresh.isRefreshing = false
            pcAdapter.submitList(pcs)

            binding.tvEmptyState.visibility = if (pcs.isEmpty()) View.VISIBLE else View.GONE
            binding.recyclerView.visibility = if (pcs.isEmpty()) View.GONE else View.VISIBLE
        }

        viewModel.operationResult.observe(this) { result ->
            result.onSuccess { message ->
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }.onFailure { error ->
                if (error.message?.contains("Unauthorized") == true) {
                    // Session expired, go back to login
                    navigateToLogin()
                } else {
                    Toast.makeText(this, "Error: ${error.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    override fun onRefresh() {
        viewModel.loadPCs()
    }

    override fun onResume() {
        super.onResume()
        // Refresh the list when returning from other activities
        viewModel.loadPCs()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.dashboard_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_refresh -> {
                viewModel.loadPCs()
                true
            }
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                true
            }
            R.id.action_logout -> {
                lifecycleScope.launch {
                    viewModel.logout()
                    navigateToLogin()
                }
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showShutdownDialog(pc: com.wakestation.android.data.model.PC) {
        if (!pc.canShutdown) {
            Toast.makeText(this, "PC is offline or daemon not available", Toast.LENGTH_SHORT).show()
            return
        }

        // Check if credentials are saved
        if (app.preferenceManager.saveShutdownCredentials &&
            app.preferenceManager.shutdownUsername.isNotEmpty() &&
            app.preferenceManager.shutdownPassword.isNotEmpty()) {

            // Use saved credentials with biometric authentication
            showBiometricShutdownDialog(pc)
        } else {
            // Show manual credential input dialog
            showManualShutdownDialog(pc)
        }
    }

    private fun showBiometricShutdownDialog(pc: com.wakestation.android.data.model.PC) {
        if (biometricHelper.isBiometricAvailable()) {
            biometricHelper.authenticateWithBiometric(
                title = "Shutdown ${pc.hostname}",
                subtitle = "Authenticate to use saved credentials for shutdown",
                onSuccess = {
                    // Use saved credentials
                    val username = app.preferenceManager.shutdownUsername
                    val password = app.preferenceManager.shutdownPassword
                    viewModel.shutdownPC(pc, username, password)
                },
                onError = { error ->
                    Toast.makeText(this, "Authentication failed: $error", Toast.LENGTH_SHORT).show()
                    // Fallback to manual input
                    showManualShutdownDialog(pc)
                }
            )
        } else {
            // Biometric not available, ask for device PIN/password
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("Shutdown ${pc.hostname}")
                .setMessage("Biometric authentication not available. Use saved credentials?")
                .setPositiveButton("Use Saved") { _, _ ->
                    val username = app.preferenceManager.shutdownUsername
                    val password = app.preferenceManager.shutdownPassword
                    viewModel.shutdownPC(pc, username, password)
                }
                .setNegativeButton("Enter Manually") { _, _ ->
                    showManualShutdownDialog(pc)
                }
                .setNeutralButton("Cancel", null)
                .show()
        }
    }

    private fun showManualShutdownDialog(pc: com.wakestation.android.data.model.PC) {
        // Create custom layout for username/password input
        val linearLayout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 50, 50, 50)
        }

        val usernameInput = android.widget.EditText(this).apply {
            hint = "Username"
            inputType = android.text.InputType.TYPE_CLASS_TEXT
        }

        val passwordInput = android.widget.EditText(this).apply {
            hint = "Password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        linearLayout.addView(usernameInput)
        linearLayout.addView(passwordInput)

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Shutdown ${pc.hostname}")
            .setMessage("Enter credentials for remote shutdown:")
            .setView(linearLayout)
            .setPositiveButton("Shutdown") { _, _ ->
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

                viewModel.shutdownPC(pc, username, password)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showDeleteDialog(pc: com.wakestation.android.data.model.PC) {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Delete ${pc.hostname}")
            .setMessage("Are you sure you want to remove this PC from the list?")
            .setPositiveButton("Delete") { _, _ ->
                viewModel.deletePC(pc.mac)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun navigateToLogin() {
        val intent = Intent(this, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}