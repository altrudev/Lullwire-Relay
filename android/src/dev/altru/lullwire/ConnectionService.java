// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.app.Notification;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

/**
 * "Stay connected in the background": a foreground service with a quiet notification,
 * so Android keeps the app's process (and its one connection to your relay) alive while
 * the app is closed. If Android restarts the service on its own, it starts the app
 * without a screen. No Google services and no push servers are involved.
 */
public class ConnectionService extends Service {
    static final int ID = 1;

    static void start(Context c) {
        Intent i = new Intent(c, ConnectionService.class);
        try {
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
        } catch (RuntimeException e) { // Android refused (started from the background): retried when the app opens
        }
    }

    static void stop(Context c) { c.stopService(new Intent(c, ConnectionService.class)); }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification n = Notify.connected(this);
        if (Build.VERSION.SDK_INT >= 34) startForeground(ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(ID, n);
        if (!Prefs.background(this)) { stopSelf(); return START_NOT_STICKY; }
        if (Shell.web == null) Shell.ensure(getApplicationContext(), null); // restarted without a screen
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (Shell.activity == null && !Prefs.background(this)) Shell.destroy();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
