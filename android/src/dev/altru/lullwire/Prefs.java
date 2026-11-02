// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.content.Context;

/** The one setting Android needs before the web app has started: background mode. */
final class Prefs {
    private Prefs() { }

    static boolean background(Context c) {
        return c.getSharedPreferences("lullwire", Context.MODE_PRIVATE).getBoolean("background", false);
    }

    static void setBackground(Context c, boolean on) {
        c.getSharedPreferences("lullwire", Context.MODE_PRIVATE).edit().putBoolean("background", on).apply();
    }
}
