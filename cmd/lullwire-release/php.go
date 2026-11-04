// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// phpBundle writes the single-file edition: one PHP file holding the "lite" relay and
// every app file, so a person with ordinary web hosting uploads one file and is done.
//
// Layout: a small router, then web/relay.php unchanged, then __halt_compiler() and the
// app files. The files are stored byte for byte (the signed release.json still matches)
// after a one-line JSON index of {name: [offset, length, etag]}.
//
// URLs, for an upload at https://example.com/lullwire-relay.php:
//
//	…/lullwire-relay.php            redirects to …/lullwire-relay.php/
//	…/lullwire-relay.php/           the app (index.html), and its files next to it
//	…/lullwire-relay.php/relay.php  the relay API (where the app looks by default)
func phpBundle(dir, outDir string) (string, error) {
	m, err := verify(dir)
	if err != nil {
		return "", fmt.Errorf("the app in %s is not a signed release (%w); run sign first", dir, err)
	}
	relay, err := os.ReadFile(filepath.Join(dir, "relay.php"))
	if err != nil {
		return "", err
	}
	code, ok := bytes.CutPrefix(relay, []byte("<?php"))
	if !ok || bytes.HasSuffix(bytes.TrimSpace(code), []byte("?>")) {
		return "", errors.New("relay.php must start with <?php and have no closing ?> tag")
	}
	if bytes.Contains(code, []byte("__halt_compiler")) {
		return "", errors.New("relay.php must not contain __halt_compiler")
	}

	names := []string{"release.json", "sw.js"}
	for n := range m.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	type entry [3]any // offset, length, etag
	index := map[string]entry{}
	var data bytes.Buffer
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			return "", err
		}
		h := sha256.Sum256(b)
		index[n] = entry{data.Len(), len(b), `"` + hex.EncodeToString(h[:8]) + `"`}
		data.Write(b)
	}
	idx, _ := json.Marshal(index)

	var out bytes.Buffer
	out.WriteString(strings.ReplaceAll(phpRouter, "{{VERSION}}", m.Version))
	out.Write(bytes.TrimRight(code, " \t\r\n"))
	out.WriteString("\n__halt_compiler();")
	out.Write(idx)
	out.WriteByte('\n')
	out.Write(data.Bytes())

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	// No version in the name: the address is baked into invites, so an update must
	// replace the file under the same name.
	path := filepath.Join(outDir, "lullwire-relay.php")
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		return "", err
	}
	fmt.Printf("built %s: relay + %d app files (%d KB), web release %s, key %s\n",
		path, len(names), out.Len()/1024, m.Version, fingerprint(m.Key))
	return path, nil
}

// phpRouter runs before relay.php's own code. It serves app files and returns early;
// only requests for the relay API fall through to the relay below it. It defines no
// named functions or globals that relay.php could collide with.
const phpRouter = `<?php
// Lullwire Relay {{VERSION}}, single-file edition: the app and a messages-only relay in one file.
//
// To host it: upload this file to any web hosting with PHP 7.4+ and HTTPS (cPanel and
// most shared hosts), then open https://your-site/<this file's name>/ in a browser and
// create your profile there. Invites you make carry your relay's address.
//
// It keeps mail in a folder named after this file (lullwire-relay-data for
// lullwire-relay.php, k7q4mxp2-data for k7q4mxp2.php), outside your public web folder
// when the host allows it (otherwise next to this file, locked with .htaccess).
//
// To make it hard to find, rename this file to something random before you first use
// it (for example k7q4mxp2ab.php): only people with your invites know the address, and
// nothing in the address or the data folder's name says what it is. Rename it later and
// it starts with an empty data folder unless you rename that folder to match.
// Voice and video calls need the Go relay (lullwire-relay); see docs/SELF-HOSTING.md.
//
// Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later
// Source and documentation: https://github.com/altrudev/Lullwire-Relay

(function () {
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $script = (string)($_SERVER['SCRIPT_NAME'] ?? '');
    $sub = isset($_SERVER['PATH_INFO']) ? (string)$_SERVER['PATH_INFO'] : '';
    if ($sub === '' && $script !== '') { // some servers leave PATH_INFO out: take it from the URL
        $uri = rawurldecode((string)strtok((string)($_SERVER['REQUEST_URI'] ?? ''), '?'));
        if (strpos($uri, $script . '/') === 0) $sub = substr($uri, strlen($script));
    }

    // The relay API: fall through to relay.php below, with a safe data folder.
    if ($sub === '/relay.php' || $sub === '/relay') {
        if (!defined('LULLWIRE_DATA') && !getenv('LULLWIRE_DATA') && !getenv('HUSH_DATA') && !is_file(__DIR__ . '/relay.config.php')) {
            // Named after this file, so a renamed (hidden) copy doesn't announce itself.
            $base = preg_replace('/[^A-Za-z0-9_-]/', '_', basename(__FILE__, '.php'));
            $dataName = ($base === '' ? 'relay' : $base) . '-data';
            // Prefer the folder above the public web folder (the hosting account's home on
            // cPanel), so mail never sits under the web root at all.
            $web = realpath((string)($_SERVER['DOCUMENT_ROOT'] ?? '')) ?: __DIR__;
            $up = dirname($web);
            $outside = $up . '/' . $dataName;
            $here = realpath(__DIR__) ?: __DIR__;
            $usable = $up !== '/' && $up !== $web && strpos($here . '/', $up . '/') === 0 &&
                (@is_dir($outside) || (@is_dir($up) && @is_writable($up)));
            define('LULLWIRE_DATA', $usable ? $outside : __DIR__ . '/' . $dataName);
        }
        return;
    }

    header('Content-Security-Policy: frame-ancestors \'none\'');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    if ($sub === '') { // the app's files are addressed relative to ".../<this file>/"
        if ($method === 'GET' || $method === 'HEAD') {
            header('Location: ' . $script . '/', true, 301);
        } else {
            http_response_code(405);
        }
        exit;
    }
    if ($method !== 'GET' && $method !== 'HEAD') {
        header('Allow: GET, HEAD');
        http_response_code(405);
        exit;
    }
    $name = $sub === '/' ? 'index.html' : substr($sub, 1);
    $f = fopen(__FILE__, 'rb');
    fseek($f, __COMPILER_HALT_OFFSET__);
    $index = json_decode((string)fgets($f), true);
    if (!is_array($index) || !isset($index[$name]) || !is_array($index[$name])) {
        header('Content-Type: text/plain; charset=utf-8');
        http_response_code(404);
        echo "Not found\n";
        exit;
    }
    list($off, $len, $etag) = $index[$name];
    $types = ['html' => 'text/html; charset=utf-8', 'js' => 'text/javascript; charset=utf-8',
        'css' => 'text/css; charset=utf-8', 'json' => 'application/json', 'svg' => 'image/svg+xml',
        'png' => 'image/png', 'txt' => 'text/plain; charset=utf-8'];
    $ext = strtolower((string)pathinfo($name, PATHINFO_EXTENSION));
    header('Content-Type: ' . ($types[$ext] ?? 'application/octet-stream'));
    header('Cache-Control: no-cache');
    header('ETag: ' . $etag);
    $match = (string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? '');
    if ($match !== '' && in_array($etag, array_map('trim', explode(',', $match)), true)) {
        http_response_code(304);
        exit;
    }
    header('Content-Length: ' . $len);
    if ($method === 'GET') {
        fseek($f, ftell($f) + $off);
        $out = fopen('php://output', 'wb');
        stream_copy_to_stream($f, $out, $len);
    }
    exit;
})();
`
