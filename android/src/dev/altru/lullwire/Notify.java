// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * Notifications. The page decides what they say: by default only "New message" or
 * "Incoming call", with no names, unless "Show names in notifications" is on. Message
 * text is never shown on the lock screen.
 */
final class Notify {
    static final String CONN = "connection", MSG = "messages", CALL = "calls";
    static final int MSG_ID = 2, CALL_ID = 3;

    private Notify() { }

    static NotificationManager nm(Context c) {
        NotificationManager m = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && m.getNotificationChannel(MSG) == null) {
            NotificationChannel conn = new NotificationChannel(CONN, "Connection", NotificationManager.IMPORTANCE_MIN);
            conn.setDescription("Shown while Lullwire Relay stays connected in the background");
            conn.setShowBadge(false);
            NotificationChannel msg = new NotificationChannel(MSG, "Messages", NotificationManager.IMPORTANCE_HIGH);
            msg.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
            NotificationChannel call = new NotificationChannel(CALL, "Calls", NotificationManager.IMPORTANCE_HIGH);
            call.setLockscreenVisibility(Notification.VISIBILITY_PRIVATE);
            m.createNotificationChannel(conn);
            m.createNotificationChannel(msg);
            m.createNotificationChannel(call);
        }
        return m;
    }

    static PendingIntent openApp(Context c) {
        Intent i = new Intent(c, MainActivity.class).setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    static Notification.Builder builder(Context c, String channel) {
        nm(c);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(c, channel) : new Notification.Builder(c);
        return b.setSmallIcon(R.mipmap.ic_launcher).setContentIntent(openApp(c));
    }

    static Notification connected(Context c) {
        return builder(c, CONN).setContentTitle("Lullwire Relay").setContentText("Connected to your relay")
                .setOngoing(true).setShowWhen(false).build();
    }

    static void show(Context c, boolean call, String title, String text) {
        Notification n = builder(c, call ? CALL : MSG).setContentTitle(title).setContentText(text)
                .setAutoCancel(true).setCategory(call ? Notification.CATEGORY_CALL : Notification.CATEGORY_MESSAGE)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .setPublicVersion(builder(c, call ? CALL : MSG).setContentTitle("Lullwire Relay")
                        .setContentText(call ? "Incoming call" : "New message").build())
                .build();
        try { nm(c).notify(call ? CALL_ID : MSG_ID, n); } catch (SecurityException ignored) { } // notifications not allowed
    }

    static void cancelCall(Context c) { nm(c).cancel(CALL_ID); }
}
