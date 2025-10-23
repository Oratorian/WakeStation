package com.wakestation.android.data.repository

import android.content.Context
import com.wakestation.android.network.VolleyApiService
import com.wakestation.android.network.LoginRequest
import com.wakestation.android.network.ApiResult
import com.wakestation.android.utils.PreferenceManager
import com.wakestation.android.utils.SecureTokenManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class AuthRepository(
    private val context: Context,
    private val apiService: VolleyApiService,
    private val preferenceManager: PreferenceManager
) {
    private val tokenManager = SecureTokenManager(context)

    suspend fun login(username: String, password: String, remember: Boolean = true): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                android.util.Log.d("AuthRepository", "Starting login request for user: $username")

                when (val response = apiService.loginJson(LoginRequest(username, password, remember))) {
                    is ApiResult.Success -> {
                        android.util.Log.d("AuthRepository", "Login response: ${response.data}")

                        if (response.data.success) {
                            // Login successful - save credentials if remember is enabled
                            if (remember) {
                                preferenceManager.username = username
                                preferenceManager.rememberLogin = true
                            }

                            val message = response.data.message
                            android.util.Log.d("AuthRepository", "Login success, returning: $message")
                            Result.success(message)
                        } else {
                            val message = response.data.message
                            android.util.Log.d("AuthRepository", "Login failed from response: $message")
                            Result.failure(Exception(message))
                        }
                    }
                    is ApiResult.Error -> {
                        android.util.Log.d("AuthRepository", "Login failed: ${response.message}")
                        Result.failure(Exception(response.message))
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e("AuthRepository", "Login exception: ${e.message}", e)
                Result.failure(e)
            }
        }
    }

    suspend fun logout(): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                android.util.Log.d("AuthRepository", "Starting logout request")

                when (val response = apiService.logout()) {
                    is ApiResult.Success -> {
                        android.util.Log.d("AuthRepository", "Logout successful, clearing credentials and tokens")
                        // Clear saved credentials if logout is successful
                        if (!preferenceManager.rememberLogin) {
                            preferenceManager.username = ""
                        }
                        // Tokens are already cleared in apiService.logout()
                        Result.success(Unit)
                    }
                    is ApiResult.Error -> {
                        android.util.Log.d("AuthRepository", "Logout failed: ${response.message}")
                        // Even if logout fails due to network issues, clear local credentials
                        if (!preferenceManager.rememberLogin) {
                            preferenceManager.username = ""
                        }
                        // Tokens are already cleared in apiService.logout()
                        Result.success(Unit) // Consider logout successful for app state
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e("AuthRepository", "Logout exception: ${e.message}", e)
                // Even if logout fails due to network issues, clear local credentials
                if (!preferenceManager.rememberLogin) {
                    preferenceManager.username = ""
                }
                // Clear tokens locally
                tokenManager.clearTokens()
                Result.success(Unit) // Consider logout successful for app state
            }
        }
    }

    fun isLoggedIn(): Boolean {
        // Check if user has valid JWT tokens
        val hasTokens = tokenManager.hasValidTokens()
        val hasUsername = preferenceManager.rememberLogin && preferenceManager.username.isNotEmpty()

        android.util.Log.d("AuthRepository", "isLoggedIn - hasTokens: $hasTokens, hasUsername: $hasUsername")

        return hasTokens && hasUsername
    }

    fun getSavedUsername(): String {
        return preferenceManager.username
    }

    fun clearCredentials() {
        preferenceManager.username = ""
        preferenceManager.rememberLogin = false
        tokenManager.clearTokens()
        android.util.Log.d("AuthRepository", "All credentials and tokens cleared")
    }
}