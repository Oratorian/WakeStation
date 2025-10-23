package com.wakestation.android.network

import android.content.Context
import com.android.volley.Request
import com.android.volley.RequestQueue
import com.android.volley.toolbox.JsonObjectRequest
import com.android.volley.toolbox.StringRequest
import com.android.volley.toolbox.Volley
import com.android.volley.toolbox.BasicNetwork
import com.android.volley.toolbox.HurlStack
import com.android.volley.toolbox.DiskBasedCache
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.wakestation.android.data.model.*
import com.wakestation.android.utils.PreferenceManager
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import java.io.File
import java.net.CookieHandler
import java.net.CookieManager
import java.net.CookiePolicy
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class VolleyApiService(private val context: Context) {

    private val requestQueue: RequestQueue by lazy {
        // Use default Volley implementation
        Volley.newRequestQueue(context.applicationContext)
    }

    private val gson = Gson()
    private val preferenceManager = PreferenceManager(context)
    private val tokenManager = com.wakestation.android.utils.SecureTokenManager(context)

    private fun getBaseUrl(): String {
        val url = preferenceManager.serverUrl
        return if (url.endsWith("/")) url else "$url/"
    }

    /**
     * Add Authorization header with Bearer token to requests
     */
    private fun getAuthHeaders(): MutableMap<String, String> {
        val headers = HashMap<String, String>()
        tokenManager.getAccessToken()?.let { token ->
            headers["Authorization"] = "Bearer $token"
        }
        return headers
    }

    suspend fun loginJson(request: LoginRequest): ApiResult<LoginResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/login"

            val jsonBody = JSONObject().apply {
                put("username", request.username)
                put("password", request.password)
                put("remember", request.remember)
            }

            val jsonRequest = object : JsonObjectRequest(
                Method.POST,
                url,
                jsonBody,
                { response ->
                    try {
                        android.util.Log.d("VolleyApiService", "Raw login response: $response")

                        val loginResponse = LoginResponse(
                            success = response.getBoolean("success"),
                            message = response.optString("message", "Login successful"),
                            access_token = if (response.has("access_token")) response.getString("access_token") else null,
                            refresh_token = if (response.has("refresh_token")) response.getString("refresh_token") else null,
                            token_type = response.optString("token_type", "bearer"),
                            expires_in = response.optInt("expires_in", 900)
                        )

                        // Save JWT tokens if present
                        if (loginResponse.access_token != null && loginResponse.refresh_token != null) {
                            tokenManager.saveTokens(
                                loginResponse.access_token,
                                loginResponse.refresh_token,
                                loginResponse.expires_in ?: 900
                            )
                            android.util.Log.d("VolleyApiService", "JWT tokens saved successfully")
                        }

                        android.util.Log.d("VolleyApiService", "Parsed login response: $loginResponse")
                        continuation.resume(ApiResult.Success(loginResponse))
                    } catch (e: Exception) {
                        android.util.Log.e("VolleyApiService", "Login response parsing error: ${e.message}", e)
                        android.util.Log.e("VolleyApiService", "Raw response was: $response")
                        continuation.resume(ApiResult.Error("Login parsing failed: ${e.message}"))
                    }
                },
                { error ->
                    val errorMsg = when (error.networkResponse?.statusCode) {
                        401 -> "Invalid credentials"
                        404 -> "Server not found"
                        500 -> "Server error"
                        else -> "Login failed: ${error.message}"
                    }
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                // No auth headers needed for login
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun refreshToken(): ApiResult<RefreshTokenResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/refresh"
            val refreshToken = tokenManager.getRefreshToken()

            if (refreshToken == null) {
                continuation.resume(ApiResult.Error("No refresh token available"))
                return@suspendCancellableCoroutine
            }

            val jsonBody = JSONObject().apply {
                put("refresh_token", refreshToken)
            }

            val jsonRequest = JsonObjectRequest(
                Request.Method.POST,
                url,
                jsonBody,
                { response ->
                    try {
                        val refreshResponse = RefreshTokenResponse(
                            success = response.getBoolean("success"),
                            access_token = response.getString("access_token"),
                            refresh_token = response.getString("refresh_token"),
                            token_type = response.optString("token_type", "bearer"),
                            expires_in = response.optInt("expires_in", 900)
                        )

                        // Update tokens
                        tokenManager.saveTokens(
                            refreshResponse.access_token,
                            refreshResponse.refresh_token,
                            refreshResponse.expires_in
                        )

                        android.util.Log.d("VolleyApiService", "Token refreshed successfully")
                        continuation.resume(ApiResult.Success(refreshResponse))
                    } catch (e: Exception) {
                        android.util.Log.e("VolleyApiService", "Token refresh parsing error: ${e.message}", e)
                        continuation.resume(ApiResult.Error("Token refresh failed: ${e.message}"))
                    }
                },
                { error ->
                    val errorMsg = "Token refresh failed: ${error.message}"
                    android.util.Log.e("VolleyApiService", errorMsg)
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            )

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun logout(): ApiResult<Unit> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/logout"

            val jsonRequest = object : JsonObjectRequest(
                Method.POST,
                url,
                null,
                {
                    // Clear tokens on successful logout
                    tokenManager.clearTokens()
                    continuation.resume(ApiResult.Success(Unit))
                },
                { error ->
                    // Even if logout fails, clear tokens locally
                    tokenManager.clearTokens()
                    continuation.resume(ApiResult.Success(Unit))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun loadPCs(): ApiResult<PCListResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/load"

            val jsonRequest = object : JsonObjectRequest(
                Method.GET,
                url,
                null,
                { response ->
                    try {
                        android.util.Log.d("VolleyApiService", "Raw loadPCs response: $response")
                        val success = response.getBoolean("success")
                        val message: String? = if (response.has("message")) response.getString("message") else null
                        val pcsArray = response.optJSONArray("pcs_list")

                        val pcsList = if (pcsArray != null) {
                            val listType = object : TypeToken<List<PC>>() {}.type
                            gson.fromJson<List<PC>>(pcsArray.toString(), listType)
                        } else {
                            emptyList()
                        }

                        val pcListResponse = PCListResponse(
                            success = success,
                            pcs_list = pcsList,
                            message = message
                        )
                        android.util.Log.d("VolleyApiService", "Parsed loadPCs response: $pcListResponse")
                        continuation.resume(ApiResult.Success(pcListResponse))
                    } catch (e: Exception) {
                        android.util.Log.e("VolleyApiService", "LoadPCs parsing error: ${e.message}", e)
                        continuation.resume(ApiResult.Error("Failed to parse PC list: ${e.message}"))
                    }
                },
                { error ->
                    android.util.Log.e("VolleyApiService", "LoadPCs network error: ${error.message}", error)
                    val errorMsg = "Failed to load PCs: ${error.message}"
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun checkPCStatus(ip: String): ApiResult<StatusResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/status?ip=$ip"

            val jsonRequest = object : JsonObjectRequest(
                Method.GET,
                url,
                null,
                { response ->
                    try {
                        val statusResponse = StatusResponse(
                            success = response.getBoolean("success"),
                            status = if (response.has("status")) response.getString("status") else null,
                            daemon_available = response.optBoolean("daemon_available", false),
                            message = if (response.has("message")) response.getString("message") else null
                        )
                        continuation.resume(ApiResult.Success(statusResponse))
                    } catch (e: Exception) {
                        continuation.resumeWithException(e)
                    }
                },
                { error ->
                    val errorMsg = "Failed to check status: ${error.message}"
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun wakePC(mac: String): ApiResult<WakeResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/wake?mac=$mac"

            val jsonRequest = object : JsonObjectRequest(
                Method.POST,
                url,
                null,
                { response ->
                    try {
                        val wakeResponse = WakeResponse(
                            success = response.getBoolean("success"),
                            message = response.getString("message")
                        )
                        continuation.resume(ApiResult.Success(wakeResponse))
                    } catch (e: Exception) {
                        continuation.resumeWithException(e)
                    }
                },
                { error ->
                    val errorMsg = "Failed to wake PC: ${error.message}"
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun shutdownPC(request: ShutdownRequest): ApiResult<ShutdownResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/shutdown"

            val jsonBody = JSONObject().apply {
                put("daemon_guid", request.pc_ip) // Note: Update your ShutdownRequest model to use daemon_guid
                request.username?.let { put("username", it) }
                request.password?.let { put("password", it) }
                request.encrypted_payload?.let { put("encrypted_payload", it) }
            }

            val jsonRequest = object : JsonObjectRequest(
                Method.POST,
                url,
                jsonBody,
                { response ->
                    try {
                        val shutdownResponse = ShutdownResponse(
                            success = response.getBoolean("success"),
                            message = response.getString("message")
                        )
                        continuation.resume(ApiResult.Success(shutdownResponse))
                    } catch (e: Exception) {
                        continuation.resumeWithException(e)
                    }
                },
                { error ->
                    val errorMsg = "Failed to shutdown PC: ${error.message}"
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun addPC(request: AddPCRequest): ApiResult<PCListResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/add"

            val jsonBody = JSONObject().apply {
                put("mac", request.mac)
                put("hostname", request.hostname)
            }

            val jsonRequest = object : JsonObjectRequest(
                Method.POST,
                url,
                jsonBody,
                { response ->
                    try {
                        val success = response.getBoolean("success")
                        val message: String? = if (response.has("message")) response.getString("message") else null
                        val pcsArray = response.optJSONArray("pcs_list")

                        val pcsList = if (pcsArray != null) {
                            val listType = object : TypeToken<List<PC>>() {}.type
                            gson.fromJson<List<PC>>(pcsArray.toString(), listType)
                        } else {
                            emptyList()
                        }

                        val pcListResponse = PCListResponse(
                            success = success,
                            pcs_list = pcsList,
                            message = message
                        )
                        continuation.resume(ApiResult.Success(pcListResponse))
                    } catch (e: Exception) {
                        continuation.resumeWithException(e)
                    }
                },
                { error ->
                    val errorMsg = "Failed to add PC: ${error.message}"
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun deletePC(mac: String): ApiResult<PCListResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/delete?mac=$mac"

            val jsonRequest = object : JsonObjectRequest(
                Method.DELETE,
                url,
                null,
                { response ->
                    try {
                        val success = response.getBoolean("success")
                        val message: String? = if (response.has("message")) response.getString("message") else null
                        val pcsArray = response.optJSONArray("pcs_list")

                        val pcsList = if (pcsArray != null) {
                            val listType = object : TypeToken<List<PC>>() {}.type
                            gson.fromJson<List<PC>>(pcsArray.toString(), listType)
                        } else {
                            emptyList()
                        }

                        val pcListResponse = PCListResponse(
                            success = success,
                            pcs_list = pcsList,
                            message = message
                        )
                        continuation.resume(ApiResult.Success(pcListResponse))
                    } catch (e: Exception) {
                        continuation.resumeWithException(e)
                    }
                },
                { error ->
                    val errorMsg = "Failed to delete PC: ${error.message}"
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }

    suspend fun getEncryptionKey(): ApiResult<EncryptionKeyResponse> {
        return suspendCancellableCoroutine { continuation ->
            val url = "${getBaseUrl()}api/get_encryption_key"

            val jsonRequest = object : JsonObjectRequest(
                Method.GET,
                url,
                null,
                { response ->
                    try {
                        val encryptionResponse = EncryptionKeyResponse(
                            success = response.getBoolean("success"),
                            encryption_key = if (response.has("encryption_key")) response.getString("encryption_key") else null,
                            message = if (response.has("message")) response.getString("message") else null
                        )
                        continuation.resume(ApiResult.Success(encryptionResponse))
                    } catch (e: Exception) {
                        continuation.resumeWithException(e)
                    }
                },
                { error ->
                    val errorMsg = "Failed to get encryption key: ${error.message}"
                    continuation.resume(ApiResult.Error(errorMsg))
                }
            ) {
                override fun getHeaders(): MutableMap<String, String> {
                    return getAuthHeaders()
                }
            }

            requestQueue.add(jsonRequest)

            continuation.invokeOnCancellation {
                jsonRequest.cancel()
            }
        }
    }
}

// Simple result wrapper
sealed class ApiResult<out T> {
    data class Success<out T>(val data: T) : ApiResult<T>()
    data class Error(val message: String) : ApiResult<Nothing>()
}

// Keep existing data classes
data class LoginRequest(
    val username: String,
    val password: String,
    val remember: Boolean = true
)

data class AddPCRequest(
    val mac: String,
    val hostname: String
)

data class ShutdownRequest(
    val pc_ip: String,
    val username: String? = null,
    val password: String? = null,
    val encrypted_payload: String? = null
)