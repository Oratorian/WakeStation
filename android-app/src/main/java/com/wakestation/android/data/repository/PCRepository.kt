package com.wakestation.android.data.repository

import com.wakestation.android.data.model.PC
import com.wakestation.android.network.AddPCRequest
import com.wakestation.android.network.VolleyApiService
import com.wakestation.android.network.ShutdownRequest
import com.wakestation.android.network.ApiResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class PCRepository(private val apiService: VolleyApiService) {

    suspend fun loadPCs(): Result<List<PC>> {
        return withContext(Dispatchers.IO) {
            try {
                when (val response = apiService.loadPCs()) {
                    is ApiResult.Success -> {
                        if (response.data.success) {
                            Result.success(response.data.pcs_list ?: emptyList())
                        } else {
                            Result.failure(Exception(response.data.message ?: "Failed to load PCs"))
                        }
                    }
                    is ApiResult.Error -> {
                        // Check if it's a session expiry issue
                        if (response.message.contains("Unauthorized", ignoreCase = true)) {
                            Result.failure(Exception("Session expired - please login again"))
                        } else {
                            Result.failure(Exception(response.message))
                        }
                    }
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun checkPCStatus(ip: String): Result<Pair<String, Boolean>> {
        return withContext(Dispatchers.IO) {
            try {
                when (val response = apiService.checkPCStatus(ip)) {
                    is ApiResult.Success -> {
                        if (response.data.success) {
                            val status = response.data.status ?: "unknown"
                            val daemonAvailable = response.data.daemon_available
                            Result.success(Pair(status, daemonAvailable))
                        } else {
                            Result.failure(Exception(response.data.message ?: "Failed to check status"))
                        }
                    }
                    is ApiResult.Error -> {
                        Result.failure(Exception(response.message))
                    }
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun wakePC(mac: String): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                when (val response = apiService.wakePC(mac)) {
                    is ApiResult.Success -> {
                        if (response.data.success) {
                            Result.success(response.data.message)
                        } else {
                            Result.failure(Exception(response.data.message))
                        }
                    }
                    is ApiResult.Error -> {
                        Result.failure(Exception(response.message))
                    }
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun shutdownPC(pcIp: String, username: String? = null, password: String? = null, encryptedPayload: String? = null): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                val request = ShutdownRequest(pcIp, username, password, encryptedPayload)
                when (val response = apiService.shutdownPC(request)) {
                    is ApiResult.Success -> {
                        if (response.data.success) {
                            Result.success(response.data.message)
                        } else {
                            Result.failure(Exception(response.data.message))
                        }
                    }
                    is ApiResult.Error -> {
                        Result.failure(Exception(response.message))
                    }
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun addPC(mac: String, hostname: String): Result<List<PC>> {
        return withContext(Dispatchers.IO) {
            try {
                val request = AddPCRequest(mac, hostname)
                when (val response = apiService.addPC(request)) {
                    is ApiResult.Success -> {
                        if (response.data.success) {
                            Result.success(response.data.pcs_list ?: emptyList())
                        } else {
                            Result.failure(Exception(response.data.message ?: "Failed to add PC"))
                        }
                    }
                    is ApiResult.Error -> {
                        Result.failure(Exception(response.message))
                    }
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun deletePC(mac: String): Result<List<PC>> {
        return withContext(Dispatchers.IO) {
            try {
                when (val response = apiService.deletePC(mac)) {
                    is ApiResult.Success -> {
                        if (response.data.success) {
                            Result.success(response.data.pcs_list ?: emptyList())
                        } else {
                            Result.failure(Exception(response.data.message ?: "Failed to delete PC"))
                        }
                    }
                    is ApiResult.Error -> {
                        Result.failure(Exception(response.message))
                    }
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }

    suspend fun getEncryptionKey(): Result<String> {
        return withContext(Dispatchers.IO) {
            try {
                when (val response = apiService.getEncryptionKey()) {
                    is ApiResult.Success -> {
                        if (response.data.success && !response.data.encryption_key.isNullOrEmpty()) {
                            Result.success(response.data.encryption_key)
                        } else {
                            Result.failure(Exception(response.data.message ?: "Failed to get encryption key"))
                        }
                    }
                    is ApiResult.Error -> {
                        Result.failure(Exception(response.message))
                    }
                }
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
    }
}