// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.widget.FrameLayout;
import android.widget.Toast;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** The screen. The app itself (the WebView) lives in {@link Shell}. */
public class MainActivity extends Activity {
    static final int REQ_PERMS = 1, REQ_FILE = 2, REQ_SAVE = 3, REQ_NOTIFY = 4;

    FrameLayout root;
    PermissionRequest pendingPermission;
    ValueCallback<Uri[]> pendingFiles;
    String pendingSave;
    byte[] pendingBytes;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        // Keep chats out of screenshots, screen recordings and the recent-apps preview
        // (debug builds allow screenshots, for testing).
        if (!BuildConfig.DEBUG) getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(Color.WHITE);
        getWindow().setNavigationBarColor(Color.WHITE);
        getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                | (Build.VERSION.SDK_INT >= 26 ? View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR : 0));
        setVolumeControlStream(AudioManager.STREAM_VOICE_CALL);

        root = new FrameLayout(this);
        // Android 15 draws apps edge to edge; keep the page clear of the system bars.
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            int top, bottom, left, right;
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets i = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                top = i.top; bottom = i.bottom; left = i.left; right = i.right;
            } else {
                top = insets.getSystemWindowInsetTop(); bottom = insets.getSystemWindowInsetBottom();
                left = insets.getSystemWindowInsetLeft(); right = insets.getSystemWindowInsetRight();
            }
            v.setPadding(left, top, right, bottom);
            return insets;
        });
        setContentView(root);

        Shell.activity = this;
        String code = linkFrom(getIntent());
        boolean existed = Shell.web != null;
        WebView web = Shell.ensure(this, existed ? null : hashOf(code));
        Shell.detach(this); // in case it was attached to an earlier screen
        root.addView(web, new FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        if (existed) Shell.open(code);
        if (Prefs.background(this)) ConnectionService.start(this);
    }

    static String hashOf(String code) { return code == null ? null : code.substring(code.indexOf('#')); }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Shell.open(linkFrom(intent));
    }

    /** An invite or move link handed to the app (shared text or a lullwire:// link). */
    static String linkFrom(Intent intent) {
        if (intent == null) return null;
        String text = null;
        if (Intent.ACTION_SEND.equals(intent.getAction())) text = intent.getStringExtra(Intent.EXTRA_TEXT);
        else if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null) text = intent.getDataString();
        if (text == null) return null;
        int at = text.indexOf("#i=");
        if (at < 0) at = text.indexOf("#link=");
        if (at < 0) return null;
        int end = at;
        while (end < text.length() && !Character.isWhitespace(text.charAt(end))) end++;
        String hash = text.substring(at, end);
        return hash.matches("#(i|link)=[A-Za-z0-9_-]+") ? hash : null;
    }

    @Override
    public void onBackPressed() {
        // Go back inside the app first; leave it only from the home screen.
        if (Shell.web == null) { super.onBackPressed(); return; }
        Shell.web.evaluateJavascript("(function(){var b=document.getElementById('back');"
                + "if(b&&!b.hidden&&b.offsetParent!==null){b.click();return 1}return 0})()", r -> {
            if (!"1".equals(r)) moveTaskToBack(true);
        });
    }

    @Override
    protected void onDestroy() {
        if (Shell.activity == this) {
            Shell.activity = null;
            if (pendingPermission != null) { pendingPermission.deny(); pendingPermission = null; }
            if (pendingFiles != null) { pendingFiles.onReceiveValue(null); pendingFiles = null; }
            // With background mode on, the app keeps running without a screen.
            if (Prefs.background(this) || isChangingConfigurations()) Shell.detach(getApplicationContext());
            else Shell.destroy();
        }
        super.onDestroy();
    }

    // ----- camera and microphone -----
    void askMedia(PermissionRequest req) {
        List<String> need = new ArrayList<>();
        for (String r : req.getResources()) {
            if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(r) && !granted(Manifest.permission.CAMERA)) need.add(Manifest.permission.CAMERA);
            if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(r) && !granted(Manifest.permission.RECORD_AUDIO)) need.add(Manifest.permission.RECORD_AUDIO);
        }
        if (need.isEmpty()) { grant(req); return; }
        if (pendingPermission != null) pendingPermission.deny();
        pendingPermission = req;
        requestPermissions(need.toArray(new String[0]), REQ_PERMS);
    }

    boolean granted(String p) { return checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED; }

    /** Grant only what Android allowed; the page falls back (e.g. audio-only) for the rest. */
    void grant(PermissionRequest req) {
        List<String> ok = new ArrayList<>();
        for (String r : req.getResources()) {
            if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(r) && granted(Manifest.permission.CAMERA)) ok.add(r);
            if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(r) && granted(Manifest.permission.RECORD_AUDIO)) ok.add(r);
        }
        if (ok.isEmpty()) req.deny(); else req.grant(ok.toArray(new String[0]));
    }

    /** Android 13+ asks before an app may show notifications. */
    void askNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && !granted(Manifest.permission.POST_NOTIFICATIONS))
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFY);
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        if (code == REQ_PERMS && pendingPermission != null) { grant(pendingPermission); pendingPermission = null; }
    }

    // ----- files -----
    boolean chooseFile(ValueCallback<Uri[]> callback, WebChromeClient.FileChooserParams params) {
        if (pendingFiles != null) pendingFiles.onReceiveValue(null);
        pendingFiles = callback;
        try {
            startActivityForResult(params.createIntent(), REQ_FILE);
        } catch (Exception e) {
            pendingFiles = null; return false;
        }
        return true;
    }

    void saveBytes(String name, String type, String data) {
        try {
            pendingBytes = android.util.Base64.decode(data, android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, "Could not save the file", Toast.LENGTH_LONG).show(); return;
        }
        pendingSave = null;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType(type == null || type.isEmpty() ? "application/octet-stream" : type).putExtra(Intent.EXTRA_TITLE, name);
        startActivityForResult(i, REQ_SAVE);
    }

    void saveFile(String name, String text) {
        pendingBytes = null;
        pendingSave = text;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, name);
        startActivityForResult(i, REQ_SAVE);
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        if (code == REQ_FILE && pendingFiles != null) {
            pendingFiles.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data));
            pendingFiles = null;
        } else if (code == REQ_SAVE && pendingBytes != null) {
            byte[] bytes = pendingBytes; pendingBytes = null;
            if (result != RESULT_OK || data == null || data.getData() == null) return;
            try (OutputStream out = getContentResolver().openOutputStream(data.getData())) {
                out.write(bytes);
                Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(this, "Could not save the file", Toast.LENGTH_LONG).show();
            }
        } else if (code == REQ_SAVE) {
            String text = pendingSave; pendingSave = null;
            if (result != RESULT_OK || data == null || data.getData() == null || text == null) return;
            try (OutputStream out = getContentResolver().openOutputStream(data.getData())) {
                out.write(text.getBytes(StandardCharsets.UTF_8));
                Toast.makeText(this, "Backup saved", Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(this, "Could not save the backup", Toast.LENGTH_LONG).show();
            }
        }
    }
}
