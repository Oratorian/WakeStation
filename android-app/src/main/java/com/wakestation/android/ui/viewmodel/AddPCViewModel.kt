package com.wakestation.android.ui.viewmodel

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.wakestation.android.data.repository.PCRepository
import kotlinx.coroutines.launch

class AddPCViewModel(
    private val pcRepository: PCRepository
) : ViewModel() {

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val _addResult = MutableLiveData<Result<String>>()
    val addResult: LiveData<Result<String>> = _addResult

    fun addPC(mac: String, hostname: String) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                val result = pcRepository.addPC(mac, hostname)
                if (result.isSuccess) {
                    _addResult.value = Result.success("PC added successfully")
                } else {
                    _addResult.value = Result.failure(Exception("Failed to add PC"))
                }
            } catch (e: Exception) {
                _addResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
            }
        }
    }
}

class AddPCViewModelFactory(
    private val pcRepository: PCRepository
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(AddPCViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return AddPCViewModel(pcRepository) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}