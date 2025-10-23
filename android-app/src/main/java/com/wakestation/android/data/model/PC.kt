package com.wakestation.android.data.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class PC(
    val mac: String,
    val ip: String,
    val hostname: String,
    val status: String = "unknown",
    val daemon_available: Boolean = false,
    val ip_source: String? = null
) : Parcelable {

    val isOnline: Boolean
        get() = status == "online"

    val canShutdown: Boolean
        get() = daemon_available && isOnline
}