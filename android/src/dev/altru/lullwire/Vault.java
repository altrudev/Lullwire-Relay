// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
package dev.altru.lullwire;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Wraps the web app's vault master secret with an AES key that lives in the Android
 * Keystore (in secure hardware where the phone has it) and can't be exported. Copying
 * the app's files off the phone then isn't enough to read messages or keys.
 */
final class Vault {
    static final String ALIAS = "lullwire-vault";

    private Vault() { }

    static SecretKey key(boolean create) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) return (SecretKey) ks.getKey(ALIAS, null);
        if (!create) return null;
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        g.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return g.generateKey();
    }

    /** base64(secret) -> base64(iv | AES-GCM ciphertext), or "" if the Keystore can't. */
    static String wrap(String b64) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key(true));
            byte[] iv = c.getIV(), ct = c.doFinal(Base64.decode(b64, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.encodeToString(out, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        } catch (Exception e) {
            return "";
        }
    }

    static String unwrap(String b64) {
        try {
            SecretKey k = key(false);
            if (k == null) return "";
            byte[] in = Base64.decode(b64, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, in, 0, 12));
            return Base64.encodeToString(c.doFinal(in, 12, in.length - 12), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        } catch (Exception e) {
            return "";
        }
    }

    /** After a passphrase takes over (app lock) or the app is erased. */
    static void forget() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            ks.deleteEntry(ALIAS);
        } catch (Exception ignored) { }
    }
}
