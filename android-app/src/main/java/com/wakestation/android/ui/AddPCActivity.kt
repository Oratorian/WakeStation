package com.wakestation.android.ui

import android.os.Bundle
import android.view.MenuItem
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import com.wakestation.android.WakeStationApplication
import com.wakestation.android.databinding.ActivityAddPcBinding
import com.wakestation.android.ui.viewmodel.AddPCViewModel
import com.wakestation.android.ui.viewmodel.AddPCViewModelFactory

class AddPCActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAddPcBinding
    private lateinit var app: WakeStationApplication

    private val viewModel: AddPCViewModel by viewModels {
        AddPCViewModelFactory(app.pcRepository)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        app = application as WakeStationApplication
        binding = ActivityAddPcBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupToolbar()
        setupViews()
        observeViewModel()
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.apply {
            title = "Add PC"
            setDisplayHomeAsUpEnabled(true)
        }
    }

    private fun setupViews() {
        binding.btnAdd.setOnClickListener {
            val hostname = binding.etHostname.text.toString().trim()
            val mac = binding.etMac.text.toString().trim()

            if (validateInput(hostname, mac)) {
                viewModel.addPC(mac, hostname)
            }
        }
    }

    private fun observeViewModel() {
        viewModel.isLoading.observe(this) { isLoading ->
            binding.btnAdd.isEnabled = !isLoading
            binding.progressBar.visibility = if (isLoading)
                android.view.View.VISIBLE else android.view.View.GONE
        }

        viewModel.addResult.observe(this) { result ->
            result.onSuccess {
                Toast.makeText(this, "PC added successfully", Toast.LENGTH_SHORT).show()
                finish()
            }.onFailure { error ->
                Toast.makeText(this, "Error: ${error.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun validateInput(hostname: String, mac: String): Boolean {
        if (hostname.isEmpty()) {
            binding.etHostname.error = "Hostname is required"
            return false
        }

        if (mac.isEmpty()) {
            binding.etMac.error = "MAC address is required"
            return false
        }

        // Basic MAC address validation
        val macPattern = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        if (!mac.matches(macPattern.toRegex())) {
            binding.etMac.error = "Invalid MAC address format (use AA:BB:CC:DD:EE:FF)"
            return false
        }

        return true
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