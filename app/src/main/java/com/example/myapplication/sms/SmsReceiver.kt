package com.example.myapplication.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        // Ensure notification channel exists (Android 8+)
        createThreatsChannel(context)

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val body = messages.joinToString(" ") { it.displayMessageBody ?: "" }

        val isThreat = looksSuspicious(body)
        if (!isThreat) return

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Suspicious SMS detected")
            .setContentText(body.take(96))
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        NotificationManagerCompat.from(context)
            .notify((System.currentTimeMillis() % 1_000_000).toInt(), notification)
    }

    private fun looksSuspicious(text: String): Boolean {
        if (text.isBlank()) return false
        val t = text.lowercase()
        val keywords = listOf(
            "verify", "verification", "bank", "account", "suspend", "blocked",
            "otp", "one-time", "pay now", "urgent", "click", "link", "password"
        )
        return keywords.any { it in t }
    }

    private fun createThreatsChannel(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = NotificationManagerCompat.from(context)
        val exists = nm.notificationChannels.any { it.id == CHANNEL_ID }
        if (exists) return
        val channel = NotificationChannelCompat.Builder(
            CHANNEL_ID,
            NotificationManagerCompat.IMPORTANCE_HIGH
        ).setName("Threat Alerts").setDescription("Notifications for suspicious SMS")
            .build()
        nm.createNotificationChannel(channel)
    }

    companion object {
        private const val CHANNEL_ID = "threats"
    }
}


