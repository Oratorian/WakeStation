package com.wakestation.android.ui.viewmodel

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.wakestation.android.data.repository.AuthRepository
import com.wakestation.android.utils.PreferenceManager
import kotlinx.coroutines.launch

class LoginViewModel(
    private val authRepository: AuthRepository,
    private val preferenceManager: PreferenceManager
) : ViewModel() {

    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading

    private val _loginResult = MutableLiveData<Result<String>>()
    val loginResult: LiveData<Result<String>> = _loginResult

    fun login(username: String, password: String, remember: Boolean) {
        // Prevent multiple concurrent login attempts
        if (_isLoading.value == true) {
            android.util.Log.d("LoginViewModel", "Login already in progress, ignoring new request")
            return
        }

        viewModelScope.launch {
            _isLoading.value = true
            android.util.Log.d("LoginViewModel", "Starting login for user: $username")
            try {
                val result = authRepository.login(username, password, remember)
                android.util.Log.d("LoginViewModel", "Login result: ${result.isSuccess}")
                _loginResult.value = result
            } catch (e: Exception) {
                android.util.Log.e("LoginViewModel", "Login exception: ${e.message}", e)
                _loginResult.value = Result.failure(e)
            } finally {
                _isLoading.value = false
                android.util.Log.d("LoginViewModel", "Login attempt completed")
            }
        }
    }
}

class LoginViewModelFactory(
    private val authRepository: AuthRepository,
    private val preferenceManager: PreferenceManager
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(LoginViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return LoginViewModel(authRepository, preferenceManager) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}