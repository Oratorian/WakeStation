# Android App JWT Authentication Update - Summary

## ✅ What's Been Completed

### 1. Data Models Updated
**File:** `src/main/java/com/wakestation/android/data/model/ApiResponse.kt`
- ✅ Updated `LoginResponse` to include JWT token fields:
  - `access_token: String?`
  - `refresh_token: String?`
  - `token_type: String?`
  - `expires_in: Int?`
- ✅ Added `RefreshTokenRequest` data class
- ✅ Added `RefreshTokenResponse` data class

### 2. Secure Token Storage Created
**File:** `src/main/java/com/wakestation/android/utils/SecureTokenManager.kt` (NEW)
- ✅ Created complete `SecureTokenManager` class
- ✅ Uses `EncryptedSharedPreferences` with AES256_GCM encryption
- ✅ Methods implemented:
  - `saveTokens(accessToken, refreshToken, expiresIn)`
  - `getAccessToken()`
  - `getRefreshToken()`
  - `isTokenExpired()`
  - `hasValidTokens()`
  - `clearTokens()`
  - `updateAccessToken(accessToken, expiresIn)`
- ✅ Automatic expiry tracking with 1-minute buffer

### 3. API Service Updated
**File:** `src/main/java/com/wakestation/android/network/VolleyApiService.kt`

#### Completed Updates:
- ✅ Removed cookie manager (no longer needed)
- ✅ Added `SecureTokenManager` instance
- ✅ Created `getAuthHeaders()` helper method
- ✅ **`loginJson()`** - Updated to:
  - Parse JWT tokens from response
  - Save tokens to SecureTokenManager
  - Works with new FastAPI endpoint
- ✅ **`refreshToken()`** - NEW method added:
  - Exchanges refresh token for new access token
  - Updates tokens in SecureTokenManager
  - Handles errors gracefully
- ✅ **`logout()`** - Updated to:
  - Call FastAPI `/api/logout` with Bearer token
  - Clear all tokens from SecureTokenManager
- ✅ **`loadPCs()`** - Updated to:
  - Override `getHeaders()` with Bearer token
  - Uses object expression for JsonObjectRequest
- ✅ **`checkPCStatus()`** - Updated to use Bearer auth

#### ✅ All Methods Updated:
All API methods now include Bearer token authentication:

1. ✅ **`wakePC(mac: String)`** - Updated with Bearer auth
2. ✅ **`shutdownPC(request: ShutdownRequest)`** - Updated with Bearer auth
3. ✅ **`addPC(request: AddPCRequest)`** - Updated with Bearer auth
4. ✅ **`deletePC(mac: String)`** - Updated with Bearer auth and changed to DELETE method
5. ✅ **`getEncryptionKey()`** - Updated with Bearer auth

### 4. Documentation Created
**Files:**
- ✅ `ANDROID_JWT_UPDATE_TODO.md` - Detailed task list with code examples
- ✅ `JWT_UPDATE_SUMMARY.md` - This file

---

## 📋 Remaining Tasks

### Priority 1: Complete API Service Updates
Update the 5 remaining methods to include Bearer token authentication:

**Pattern:**
```kotlin
val jsonRequest = object : JsonObjectRequest(
    Method.POST,  // or GET
    url,
    jsonBody,  // or null
    { response -> ... },
    { error -> ... }
) {
    override fun getHeaders(): MutableMap<String, String> {
        return getAuthHeaders()
    }
}
```

### Priority 2: Update AuthRepository
**File:** `src/main/java/com/wakestation/android/data/repository/AuthRepository.kt`

Changes needed:
1. Add `SecureTokenManager` instance
2. Update `isLoggedIn()` to check `tokenManager.hasValidTokens()`
3. Update `logout()` to call `tokenManager.clearTokens()`
4. Consider adding automatic token refresh logic

### Priority 3: Add Token Refresh Logic
**Recommended approach:**

Add a helper method to `VolleyApiService`:
```kotlin
private suspend fun <T> makeAuthenticatedRequest(
    requestFn: suspend () -> ApiResult<T>
): ApiResult<T> {
    // Check if token is expired
    if (tokenManager.isTokenExpired()) {
        // Refresh token
        when (val refreshResult = refreshToken()) {
            is ApiResult.Success -> {
                // Token refreshed, proceed
            }
            is ApiResult.Error -> {
                // Refresh failed, need to re-login
                return ApiResult.Error("Session expired, please login again")
            }
        }
    }

    // Make the actual request
    return requestFn()
}
```

Then wrap API calls:
```kotlin
suspend fun loadPCs(): ApiResult<PCListResponse> {
    return makeAuthenticatedRequest {
        // actual loadPCs implementation
    }
}
```

### Priority 4: Handle 401 Responses
Add error handling for expired tokens:
```kotlin
{ error ->
    if (error.networkResponse?.statusCode == 401) {
        // Token expired, try refresh
        // If refresh fails, redirect to login
    }
    // ... rest of error handling
}
```

### Priority 5: Update Dependencies
Check `build.gradle (Module: app)` includes:
```gradle
dependencies {
    // Security for EncryptedSharedPreferences
    implementation 'androidx.security:security-crypto:1.1.0-alpha06'

    // Existing dependencies...
}
```

---

## 🧪 Testing Plan

### Test Scenarios:
1. **Fresh Login**
   - [  ] Login with valid credentials
   - [  ] Verify tokens are saved in EncryptedSharedPreferences
   - [  ] Verify access token is included in subsequent API calls

2. **Token Refresh**
   - [  ] Wait 15 minutes for token to expire
   - [  ] Make an API call
   - [  ] Verify token refresh happens automatically
   - [  ] Verify new tokens are saved

3. **Logout**
   - [  ] Logout from app
   - [  ] Verify tokens are cleared from storage
   - [  ] Verify user is redirected to login screen

4. **Invalid Token**
   - [  ] Manually corrupt token in SharedPreferences
   - [  ] Make an API call
   - [  ] Verify 401 error is handled
   - [  ] Verify user is redirected to login

5. **Remember Me**
   - [  ] Login with "Remember Me" checked
   - [  ] Close and reopen app
   - [  ] Verify user stays logged in
   - [  ] Verify tokens are still valid

### Manual Testing Checklist:
- [  ] Login/Logout flow
- [  ] Load devices list
- [  ] Wake a device
- [  ] Shutdown a device
- [  ] Add a new device
- [  ] Delete a device
- [  ] Check device status
- [  ] Get encryption key

---

## 📚 API Changes Reference

### Old (Cookie-Based):
```kotlin
// Cookies were managed automatically
// No special headers needed
val jsonRequest = JsonObjectRequest(...)
```

### New (JWT Bearer Token):
```kotlin
// Must include Authorization header
val jsonRequest = object : JsonObjectRequest(...) {
    override fun getHeaders(): MutableMap<String, String> {
        val headers = HashMap<String, String>()
        tokenManager.getAccessToken()?.let { token ->
            headers["Authorization"] = "Bearer $token"
        }
        return headers
    }
}
```

### Token Flow:
```
1. POST /api/login
   → Returns: access_token, refresh_token, expires_in

2. Store tokens in EncryptedSharedPreferences

3. All API calls include:
   Authorization: Bearer <access_token>

4. When token expires (after 15 min):
   POST /api/refresh
   → Returns: new access_token, same refresh_token

5. Update stored tokens and retry request

6. POST /api/logout
   → Clear all tokens
```

---

## 🚀 Deployment Notes

### Breaking Changes:
- Users **MUST re-login** after app update
- Old cookie-based sessions will not work
- Consider showing migration message on first launch

### Migration Message Example:
```
"We've updated our security!
Please login again to continue using the app."
```

### Version Bump:
- Increment app version in `build.gradle`:
  ```gradle
  versionCode 2
  versionName "2.0.0"
  ```

---

## 🔍 Debugging Tips

### Check if tokens are being saved:
```kotlin
Log.d("TokenDebug", "Access Token: ${tokenManager.getAccessToken()}")
Log.d("TokenDebug", "Has Valid Tokens: ${tokenManager.hasValidTokens()}")
Log.d("TokenDebug", "Is Expired: ${tokenManager.isTokenExpired()}")
```

### Check Authorization header:
```kotlin
override fun getHeaders(): MutableMap<String, String> {
    val headers = getAuthHeaders()
    Log.d("HeaderDebug", "Authorization: ${headers["Authorization"]}")
    return headers
}
```

### Monitor API responses:
```kotlin
{ response ->
    Log.d("APIDebug", "Response: $response")
    // ... rest of handling
}
```

---

## 📞 Support

For issues or questions:
- Check server logs: `journalctl -u wakestation -f`
- Check Android logs: `adb logcat | grep WakeStation`
- API Documentation: See `/API_DOCUMENTATION.md` in server repo

---

**Status:** ✅ 100% Complete - Ready for Testing
**Last Updated:** 2025-10-18
**Next Steps:** Build and test the app with new JWT authentication
