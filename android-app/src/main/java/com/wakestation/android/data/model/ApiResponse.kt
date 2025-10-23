package com.wakestation.android.data.model

data class ApiResponse<T>(
    val success: Boolean,
    val message: String? = null,
    val data: T? = null
)

data class LoginResponse(
    val success: Boolean,
    val message: String,
    val access_token: String? = null,
    val refresh_token: String? = null,
    val token_type: String? = "bearer",
    val expires_in: Int? = 900 // 15 minutes in seconds
)

data class RefreshTokenRequest(
    val refresh_token: String
)

data class RefreshTokenResponse(
    val success: Boolean,
    val access_token: String,
    val refresh_token: String,
    val token_type: String = "bearer",
    val expires_in: Int = 900
)

data class PCListResponse(
    val success: Boolean,
    val pcs_list: List<PC>? = null,
    val message: String? = null
)

data class StatusResponse(
    val success: Boolean,
    val status: String? = null,
    val daemon_available: Boolean = false,
    val message: String? = null
)

data class WakeResponse(
    val success: Boolean,
    val message: String
)

data class ShutdownResponse(
    val success: Boolean,
    val message: String
)

data class EncryptionKeyResponse(
    val success: Boolean,
    val encryption_key: String? = null,
    val message: String? = null
)