// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.MutableContextWrapper;
import android.graphics.Color;
import android.net.Uri;
import android.view.ViewGroup;
import android.webkit.JavascriptInterface;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * The app itself: one WebView running the bundled web app from a private https origin
 * that only this app can load. It outlives the screen (MainActivity) so that, with
 * "Stay connected in the background" on, ConnectionService keeps it running and
 * messages and calls arrive while the app is closed. Nothing is fetched to show the
 * app; the only network traffic is to the relay you choose.
 */
final class Shell {
    static final String HOST = "appassets.androidplatform.net";
    static final String BASE = "https://" + HOST + "/";

    static WebView web;
    static MutableContextWrapper ctx;
    static MainActivity activity; // the screen, when it exists
    static boolean loaded;
    static String pendingLink;    // an invite link that arrived before the page was ready

    private Shell() { }

    /** Creates the WebView once; later calls only move it to the given context. */
    static WebView ensure(Context c, String hash) {
        if (web != null) {
            ctx.setBaseContext(c);
            return web;
        }
        ctx = new MutableContextWrapper(c);
        web = new WebView(ctx);
        web.setBackgroundColor(Color.parseColor("#f4f6f8"));
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
        s.setUserAgentString(s.getUserAgentString() + " LullwireAndroid/0.6" + (BuildConfig.DEBUG ? " debug" : ""));
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);
        web.addJavascriptInterface(new Bridge(c.getApplicationContext()), "LullwireAndroid");
        web.setWebViewClient(new Client(c.getApplicationContext()));
        web.setWebChromeClient(new Chrome());
        loaded = false;
        web.loadUrl(BASE + "index.html" + (hash != null ? hash : ""));
        return web;
    }

    /** Takes the WebView off the screen without stopping it (background mode). */
    static void detach(Context app) {
        if (web == null) return;
        if (web.getParent() instanceof ViewGroup) ((ViewGroup) web.getParent()).removeView(web);
        ctx.setBaseContext(app);
    }

    /** Stops the app completely (screen closed and background mode off). */
    static void destroy() {
        if (web == null) return;
        if (web.getParent() instanceof ViewGroup) ((ViewGroup) web.getParent()).removeView(web);
        web.destroy();
        web = null; ctx = null; loaded = false;
    }

    /** Hands an invite link to the page (or keeps it until the page is ready). */
    static void open(String hash) {
        if (hash == null) return;
        if (web != null && loaded) web.evaluateJavascript("window.lullwireOpen && lullwireOpen(" + JSONObject.quote(hash) + ")", null);
        else pendingLink = hash;
    }

    // ----- serving the bundled app -----
    static final Map<String, String> TYPES = new HashMap<>();
    static {
        TYPES.put("html", "text/html"); TYPES.put("js", "text/javascript"); TYPES.put("json", "application/json");
        TYPES.put("svg", "image/svg+xml"); TYPES.put("txt", "text/plain"); TYPES.put("css", "text/css");
        TYPES.put("png", "image/png"); TYPES.put("webmanifest", "application/manifest+json");
    }

    static final class Client extends WebViewClient {
        final Context app;
        Client(Context app) { this.app = app; }

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
                InputStream in = app.getAssets().open("www" + path);
                return new WebResourceResponse(type, type.startsWith("image/png") ? null : "utf-8", 200, "OK", headers, in);
            } catch (IOException e) {
                return notFound(headers);
            }
        }

        WebResourceResponse notFound(Map<String, String> headers) {
            return new WebResourceResponse("text/plain", "utf-8", 404, "Not Found", headers, new ByteArrayInputStream(new byte[0]));
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
            Uri u = req.getUrl();
            if ("https".equals(u.getScheme()) && HOST.equals(u.getHost())) return false;
            // Invite links pointing at a relay's web copy open here instead of the browser.
            String code = MainActivity.linkFrom(new Intent(Intent.ACTION_VIEW, u));
            if (code != null) { open(code); return true; }
            Activity a = activity;
            if ("https".equals(u.getScheme()) && a != null) {
                try { a.startActivity(new Intent(Intent.ACTION_VIEW, u)); } catch (Exception ignored) { }
            }
            return true;
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            loaded = true;
            String p = pendingLink; pendingLink = null;
            open(p);
        }
    }

    // ----- camera, microphone and file pickers (need the screen) -----
    static final class Chrome extends WebChromeClient {
        @Override
        public void onPermissionRequest(PermissionRequest req) {
            MainActivity a = activity;
            if (a == null || !HOST.equals(req.getOrigin().getHost())) { req.deny(); return; }
            a.askMedia(req);
        }

        // Running without a screen (background mode), a dialog has nowhere to appear:
        // answer it as "cancel" instead of letting Android fail to draw it.
        @Override
        public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
            if (activity != null) return false;
            result.cancel(); return true;
        }

        @Override
        public boolean onJsConfirm(WebView view, String url, String message, JsResult result) {
            if (activity != null) return false;
            result.cancel(); return true;
        }

        @Override
        public boolean onJsPrompt(WebView view, String url, String message, String def, JsPromptResult result) {
            if (activity != null) return false;
            result.cancel(); return true;
        }

        @Override
        public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
            MainActivity a = activity;
            return a != null && a.chooseFile(callback, params);
        }
    }

    // ----- what the page can ask of Android -----
    static final class Bridge {
        final Context app;
        Bridge(Context app) { this.app = app; }

        @JavascriptInterface
        public void share(String text) {
            MainActivity a = activity;
            if (a == null) return;
            a.runOnUiThread(() -> {
                Intent i = new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text);
                a.startActivity(Intent.createChooser(i, "Share invite"));
            });
        }

        @JavascriptInterface
        public void copy(String text) {
            MainActivity a = activity;
            if (a == null) return;
            a.runOnUiThread(() -> {
                ClipboardManager cm = (ClipboardManager) a.getSystemService(Context.CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("Lullwire Relay", text));
                Toast.makeText(a, "Copied", Toast.LENGTH_SHORT).show();
            });
        }

        /** Encrypted backup file: the user picks where it goes. */
        @JavascriptInterface
        public void saveFile(String name, String text) {
            MainActivity a = activity;
            if (a != null) a.runOnUiThread(() -> a.saveFile(name, text));
        }

        /** Background mode: keep the connection while the app is closed. */
        @JavascriptInterface
        public void setBackground(boolean on) {
            Prefs.setBackground(app, on);
            if (on) {
                MainActivity a = activity;
                if (a != null) a.runOnUiThread(a::askNotifications);
                ConnectionService.start(app);
            } else ConnectionService.stop(app);
        }

        @JavascriptInterface
        public void notify(String kind, String title, String text) {
            Notify.show(app, "call".equals(kind), title, text);
        }

        @JavascriptInterface
        public void callEnded() { Notify.cancelCall(app); }

        /** The vault's master secret, wrapped by a key in the Android Keystore. */
        @JavascriptInterface
        public String vaultWrap(String b64) { return Vault.wrap(b64); }

        @JavascriptInterface
        public String vaultUnwrap(String b64) { return Vault.unwrap(b64); }

        @JavascriptInterface
        public void vaultForget() { Vault.forget(); }
    }
}
