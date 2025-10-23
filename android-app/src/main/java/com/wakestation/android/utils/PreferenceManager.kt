package com.wakestation.android.utils

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager as AndroidXPreferenceManager

class PreferenceManager(context: Context) {
    private val sharedPreferences: SharedPreferences =
        AndroidXPreferenceManager.getDefaultSharedPreferences(context)

    companion object {
        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_USERNAME = "username"
        private const val KEY_REMEMBER_LOGIN = "remember_login"
        private const val KEY_AUTO_REFRESH = "auto_refresh"
        private const val KEY_REFRESH_INTERVAL = "refresh_interval"
        private const val KEY_SHUTDOWN_USERNAME = "shutdown_username"
        private const val KEY_SHUTDOWN_PASSWORD = "shutdown_password"
        private const val KEY_SAVE_SHUTDOWN_CREDENTIALS = "save_shutdown_credentials"
    }

    var serverUrl: String
        get() = sharedPreferences.getString(KEY_SERVER_URL, "http://192.168.1.100:8889") ?: "http://192.168.1.100:8889"
        set(value) { sharedPreferences.edit().putString(KEY_SERVER_URL, value).commit() }

    var username: String
        get() = sharedPreferences.getString(KEY_USERNAME, "") ?: ""
        set(value) = sharedPreferences.edit().putString(KEY_USERNAME, value).apply()

    var rememberLogin: Boolean
        get() = sharedPreferences.getBoolean(KEY_REMEMBER_LOGIN, false)
        set(value) = sharedPreferences.edit().putBoolean(KEY_REMEMBER_LOGIN, value).apply()

    var autoRefresh: Boolean
        get() = sharedPreferences.getBoolean(KEY_AUTO_REFRESH, true)
        set(value) = sharedPreferences.edit().putBoolean(KEY_AUTO_REFRESH, value).apply()

    var refreshInterval: Int
        get() = sharedPreferences.getInt(KEY_REFRESH_INTERVAL, 30)
        set(value) = sharedPreferences.edit().putInt(KEY_REFRESH_INTERVAL, value).apply()

    var saveShutdownCredentials: Boolean
        get() = sharedPreferences.getBoolean(KEY_SAVE_SHUTDOWN_CREDENTIALS, false)
        set(value) = sharedPreferences.edit().putBoolean(KEY_SAVE_SHUTDOWN_CREDENTIALS, value).apply()

    var shutdownUsername: String
        get() = sharedPreferences.getString(KEY_SHUTDOWN_USERNAME, "") ?: ""
        set(value) = sharedPreferences.edit().putString(KEY_SHUTDOWN_USERNAME, value).apply()

    var shutdownPassword: String
        get() = sharedPreferences.getString(KEY_SHUTDOWN_PASSWORD, "") ?: ""
        set(value) = sharedPreferences.edit().putString(KEY_SHUTDOWN_PASSWORD, value).apply()

    fun clearShutdownCredentials() {
        sharedPreferences.edit()
            .remove(KEY_SHUTDOWN_USERNAME)
            .remove(KEY_SHUTDOWN_PASSWORD)
            .putBoolean(KEY_SAVE_SHUTDOWN_CREDENTIALS, false)
            .apply()
    }

    fun clear() {
        sharedPreferences.edit().clear().apply()
    }
}