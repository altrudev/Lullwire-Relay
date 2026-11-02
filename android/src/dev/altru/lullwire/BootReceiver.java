// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Reconnects after the phone restarts or the app is updated, if background mode is on. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context c, Intent intent) {
        String a = intent.getAction();
        if ((Intent.ACTION_BOOT_COMPLETED.equals(a) || Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)) && Prefs.background(c))
            ConnectionService.start(c);
    }
}
