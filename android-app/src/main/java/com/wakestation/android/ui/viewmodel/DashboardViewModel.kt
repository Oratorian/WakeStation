package com.wakestation.android.ui.viewmodel

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.wakestation.android.data.model.PC
import com.wakestation.android.data.repository.AuthRepository
import com.wakestation.android.data.repository.PCRepository
import kotlinx.coroutines.launch

class DashboardViewModel(
    private val pcRepository: PCRepository,
    private val authRepository: AuthRepository
) : ViewModel() {

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val _pcs = MutableLiveData<List<PC>>()
    val pcs: LiveData<List<PC>> = _pcs

    private val _operationResult = MutableLiveData<Result<String>>()
    val operationResult: LiveData<Result<String>> = _operationResult

    fun loadPCs() {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val result = pcRepository.loadPCs()
                result.onSuccess { pcList ->
                    _pcs.value = pcList
                }.onFailure { error ->
                    _operationResult.value = Result.failure(error)
                }
            } finally {
                _isLoading.value = false
            }
        }
    }

    fun wakePC(mac: String) {
        viewModelScope.launch {
            val result = pcRepository.wakePC(mac)
            _operationResult.value = result

            // Refresh the list after wake attempt
            if (result.isSuccess) {
                loadPCs()
            }
        }
    }

    fun shutdownPC(pc: PC, username: String, password: String) {
        viewModelScope.launch {
            val result = pcRepository.shutdownPC(pc.ip, username, password)
            _operationResult.value = result

            // Refresh the list after shutdown attempt
            if (result.isSuccess) {
                loadPCs()
            }
        }
    }

    fun deletePC(mac: String) {
        viewModelScope.launch {
            val result = pcRepository.deletePC(mac)
            result.onSuccess { pcList ->
                _pcs.value = pcList
                _operationResult.value = Result.success("PC deleted successfully")
            }.onFailure { error ->
                _operationResult.value = Result.failure(error)
            }
        }
    }

    suspend fun logout() {
        val result = authRepository.logout()
        authRepository.clearCredentials()
        android.util.Log.d("DashboardViewModel", "Logout completed: ${result.isSuccess}")
    }
}

class DashboardViewModelFactory(
    private val pcRepository: PCRepository,
    private val authRepository: AuthRepository
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(DashboardViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return DashboardViewModel(pcRepository, authRepository) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}