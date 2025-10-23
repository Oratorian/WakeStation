# Android App JWT Authentication Update - Remaining Tasks

## ✅ Completed
1. Created `SecureTokenManager.kt` for encrypted token storage
2. Updated `ApiResponse.kt` with JWT token models
3. Added `refreshToken()` method to `VolleyApiService`
4. Updated `login()` to parse and save JWT tokens
5. Updated `logout()` to clear tokens and use Bearer auth
6. Updated `loadPCs()` to use Bearer auth
7. Added `getAuthHeaders()` helper method

## ⚠️ Remaining API Methods to Update in VolleyApiService.kt

All the following methods need to be wrapped in `object : JsonObjectRequest()` or `object : StringRequest()` and override `getHeaders()` to include Bearer token:

### To Update:
1. **checkPCStatus()** - Line ~256
2. **wakePC()** - Line ~287
3. **shutdownPC()** - Line ~318
4. **addPC()** - Line ~357
5. **deletePC()** - Line ~408
6. **getEncryptionKey()** - Line ~453

### Pattern to Follow:

**Before:**
```kotlin
val jsonRequest = JsonObjectRequest(
    Request.Method.GET,
    url,
    null,
    { response -> ... },
    { error -> ... }
)
```

**After:**
```kotlin
val jsonRequest = object : JsonObjectRequest(
    Method.GET,
    url,
    null,
    { response -> ... },
    { error -> ... }
) {
    override fun getHeaders(): MutableMap<String, String> {
        return getAuthHeaders()
    }
}
```

## 📝 AuthRepository.kt Updates Needed

Update the `isLoggedIn()` method to use `SecureTokenManager`:

```kotlin
fun isLoggedIn(): Boolean {
    // Check if user has valid JWT tokens
    return tokenManager.hasValidTokens()
}
```

Add token refresh logic before API calls if token is expired.

## 🔄 Token Refresh Strategy

Option 1: Automatic refresh on 401 response
- Intercept 401 errors
- Call `refreshToken()`
- Retry original request

Option 2: Proactive refresh
- Check `tokenManager.isTokenExpired()` before each API call
- Call `refreshToken()` if needed
- Then proceed with original call

**Recommendation: Use Option 2** (proactive) - implement in AuthRepository or VolleyApiService

## 🧪 Testing Checklist

After completing updates:
1. [ ] Test login - verify tokens are saved
2. [ ] Test API calls with fresh token
3. [ ] Test token refresh mechanism
4. [ ] Test logout - verify tokens are cleared
5. [ ] Test 401 handling when token expires
6. [ ] Test "remember me" functionality
7. [ ] Verify EncryptedSharedPreferences working

## 📦 Required Dependencies

Check `build.gradle` includes:
```gradle
implementation 'androidx.security:security-crypto:1.1.0-alpha06'
```

## 🚀 Deployment Notes

- Old cookie-based authentication will no longer work
- Users will need to re-login after update
- Consider showing a "Please login again" message on first launch after update
