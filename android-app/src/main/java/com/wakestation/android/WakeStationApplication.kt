package com.wakestation.android

import android.app.Application
import com.wakestation.android.data.repository.AuthRepository
import com.wakestation.android.data.repository.PCRepository
import com.wakestation.android.network.VolleyApiService
import com.wakestation.android.utils.PreferenceManager

class WakeStationApplication : Application() {

    lateinit var apiService: VolleyApiService

    lateinit var authRepository: AuthRepository
        private set

    lateinit var pcRepository: PCRepository
        private set

    lateinit var preferenceManager: PreferenceManager
        private set

    override fun onCreate() {
        super.onCreate()

        preferenceManager = PreferenceManager(this)
        apiService = VolleyApiService(this)
        authRepository = AuthRepository(this, apiService, preferenceManager)
        pcRepository = PCRepository(apiService)
    }

    fun updateServerUrl(newUrl: String) {
        preferenceManager.serverUrl = newUrl
        // Volley handles URL changes automatically via PreferenceManager
        // No need to recreate the service
    }
}