// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
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
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Lullwire Relay for Android: the same web app, bundled inside the APK and served from a
 * private https origin that only this app can load. Nothing is fetched to show the
 * app itself; the only network traffic is to the relay you choose.
 */
public class MainActivity extends Activity {
    static final String HOST = "appassets.androidplatform.net";
    static final String BASE = "https://" + HOST + "/";
    static final int REQ_PERMS = 1, REQ_FILE = 2, REQ_SAVE = 3;

    WebView web;
    PermissionRequest pendingPermission;
    ValueCallback<Uri[]> pendingFiles;
    String pendingSave;
    boolean loaded;

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

        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#f4f6f8"));
        // Android 15 draws apps edge to edge; keep the page clear of the system bars.
        web.setOnApplyWindowInsetsListener((v, insets) -> {
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
        setContentView(web);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setGeolocationEnabled(false);
        s.setSupportMultipleWindows(false);
        s.setJavaScriptCanOpenWindowsAutomatically(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setSaveFormData(false);
        s.setUserAgentString(s.getUserAgentString() + " LullwireAndroid/0.5" + (BuildConfig.DEBUG ? " debug" : ""));
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);

        web.addJavascriptInterface(new Bridge(), "LullwireAndroid");
        web.setWebViewClient(new Client());
        web.setWebChromeClient(new Chrome());

        String code = linkFrom(getIntent());
        web.loadUrl(BASE + "index.html" + (code != null ? code.substring(code.indexOf('#')) : ""));
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        String code = linkFrom(intent);
        if (code != null && loaded) web.evaluateJavascript("window.lullwireOpen && lullwireOpen(" + JSONObject.quote(code) + ")", null);
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
        web.evaluateJavascript("(function(){var b=document.getElementById('back');"
                + "if(b&&!b.hidden&&b.offsetParent!==null){b.click();return 1}return 0})()", r -> {
            if (!"1".equals(r)) moveTaskToBack(true);
        });
    }

    @Override
    protected void onDestroy() {
        if (web != null) { web.destroy(); web = null; }
        super.onDestroy();
    }

    // ----- serving the bundled app -----
    static final Map<String, String> TYPES = new HashMap<>();
    static {
        TYPES.put("html", "text/html"); TYPES.put("js", "text/javascript"); TYPES.put("json", "application/json");
        TYPES.put("svg", "image/svg+xml"); TYPES.put("txt", "text/plain"); TYPES.put("css", "text/css");
        TYPES.put("png", "image/png"); TYPES.put("webmanifest", "application/manifest+json");
    }

    class Client extends WebViewClient {
        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest req) {
            Uri u = req.getUrl();
            if (!"https".equals(u.getScheme()) || !HOST.equals(u.getHost())) return null; // relay traffic goes out as-is
            String path = u.getPath() == null ? "/" : u.getPath();
            if (path.equals("/")) path = "/index.html";
            Map<String, String> headers = new HashMap<>();
            headers.put("X-Content-Type-Options", "nosniff");
            headers.put("Cache-Control", "no-store");
            if (path.contains("..") || !path.matches("/[A-Za-z0-9_./-]+") || !"GET".equals(req.getMethod())) return notFound(headers);
            String ext = path.substring(path.lastIndexOf('.') + 1);
            String type = TYPES.get(ext);
            if (type == null) return notFound(headers);
            try {
                InputStream in = getAssets().open("www" + path);
                return new WebResourceResponse(type, type.startsWith("image/png") ? null : "utf-8", 200, "OK", headers, in);
            } catch (IOException e) {
                return notFound(headers);
            }
        }

        WebResourceResponse notFound(Map<String, String> headers) {
            return new WebResourceResponse("text/plain", "utf-8", 404, "Not Found", headers,
                    new java.io.ByteArrayInputStream(new byte[0]));
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
            Uri u = req.getUrl();
            if ("https".equals(u.getScheme()) && HOST.equals(u.getHost())) return false;
            // Invite links pointing at a relay's web copy open here instead of the browser.
            String code = linkFrom(new Intent(Intent.ACTION_VIEW, u));
            if (code != null) { view.evaluateJavascript("lullwireOpen(" + JSONObject.quote(code) + ")", null); return true; }
            if ("https".equals(u.getScheme())) {
                try { startActivity(new Intent(Intent.ACTION_VIEW, u)); } catch (Exception ignored) { }
            }
            return true;
        }

        @Override
        public void onPageFinished(WebView view, String url) { loaded = true; }
    }

    // ----- camera, microphone and file pickers -----
    class Chrome extends WebChromeClient {
        @Override
        public void onPermissionRequest(PermissionRequest req) {
            if (!HOST.equals(req.getOrigin().getHost())) { req.deny(); return; }
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

        @Override
        public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
            if (pendingFiles != null) pendingFiles.onReceiveValue(null);
            pendingFiles = callback;
            try {
                startActivityForResult(params.createIntent(), REQ_FILE);
            } catch (Exception e) {
                pendingFiles = null; return false;
            }
            return true;
        }
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

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        if (code == REQ_PERMS && pendingPermission != null) { grant(pendingPermission); pendingPermission = null; }
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        if (code == REQ_FILE && pendingFiles != null) {
            pendingFiles.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data));
            pendingFiles = null;
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

    // ----- what the page can ask of Android -----
    class Bridge {
        @JavascriptInterface
        public void share(String text) {
            runOnUiThread(() -> {
                Intent i = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text);
                startActivity(Intent.createChooser(i, "Share invite"));
            });
        }

        @JavascriptInterface
        public void copy(String text) {
            runOnUiThread(() -> {
                ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("Lullwire Relay", text));
                Toast.makeText(MainActivity.this, "Copied", Toast.LENGTH_SHORT).show();
            });
        }

        /** Encrypted backup file: the user picks where it goes. */
        @JavascriptInterface
        public void saveFile(String name, String text) {
            runOnUiThread(() -> {
                pendingSave = text;
                Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                        .setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, name);
                startActivityForResult(i, REQ_SAVE);
            });
        }
    }
}
