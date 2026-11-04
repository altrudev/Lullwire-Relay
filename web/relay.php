<?php
// Lullwire Relay — a dumb mailbox for opaque encrypted blobs.
// It never sees plaintext, sender identity, names or contacts.
//
// This is the "lite" relay for shared hosting: messages and recovery backups only.
// It is kept working and secure, but gets no new features: calls, live delivery over
// a WebSocket, invite-only mode, private paths and cover traffic need the Go relay
// (cmd/lullwire-relay). The app detects which kind it is talking to.
//
// Mailboxes: anyone holding a box id can drop a blob in; only the holder of the
// box's secret (box = first 32 hex of sha256(secret)) can read or delete.
// Recovery slots: one encrypted backup per locator, overwritable only with the
// write token chosen when it was first stored. Both are derived from the user's
// recovery words in the browser; the relay only keeps sha256(token).
//
// Configuration (optional): environment variable LULLWIRE_DATA, or a file
// relay.config.php next to this one that defines LULLWIRE_DATA. Keep it outside
// the web root unless you are on Apache (which honours the .htaccess we write).
//
// Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') exit;
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { http_response_code(405); exit; }

if (is_file(__DIR__ . '/relay.config.php')) require __DIR__ . '/relay.config.php';
// LEGACY: HUSH_* names from Hush Relay 0.5 are still read.
if (!defined('LULLWIRE_DATA') && defined('HUSH_DATA')) define('LULLWIRE_DATA', HUSH_DATA);
if (!defined('LULLWIRE_DATA')) define('LULLWIRE_DATA', getenv('LULLWIRE_DATA') ?: (getenv('HUSH_DATA') ?: __DIR__ . '/data'));

define('DATA', rtrim(LULLWIRE_DATA, '/'));
define('RECOVER', DATA . '/recover');
define('LIMITS', DATA . '/limits');
const MAX_BLOB     = 524288;        // bytes per blob (messages are padded to 32 KiB; account transfers can be larger)
const MAX_SLOT     = 786432;        // bytes per recovery slot
const MIN_BLOB     = 93;            // smallest valid envelope
const MAX_PER_BOX  = 500;           // pending messages per mailbox
const MAX_BOX_BYTES = 8388608;      // 8 MiB pending per mailbox
const TTL          = 1209600;       // 14 days, then undelivered blobs are wiped
const SLOT_TTL     = 15552000;      // 180 days untouched, then recovery slots are wiped
const MAX_WAIT     = 20;            // seconds a live (long-poll) request may wait
const MIN_FREE     = 268435456;     // refuse new data below 256 MiB free disk
const PUTS_PER_MIN = 120;           // per client IP
const SLOTS_PER_DAY = 5;            // new recovery slots per client IP
const LIVE_PER_IP  = 6;             // concurrent long-polls per client IP

function fail($code, $msg) {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode(['error' => $msg]);
    exit;
}
function ok($data = ['ok' => true]) {
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}
function body($max) {
    $in = json_decode((string)file_get_contents('php://input', false, null, 0, $max), true);
    return is_array($in) ? $in : [];
}
function hexval($v, $len) {
    return is_string($v) && preg_match('/^[0-9a-f]{' . $len . '}$/D', $v) ? $v : null;
}
function hexarg($in, $k, $len) {
    $v = hexval($in[$k] ?? null, $len);
    if ($v === null) fail(400, 'bad ' . $k);
    return $v;
}
// The real client address. Behind a local proxy or tunnel (Cloudflare Tunnel, Caddy, nginx)
// every request comes from 127.0.0.1, so the forwarded address is used instead, and only then.
// Extra proxies can be trusted with LULLWIRE_TRUSTED_PROXIES="10.0.0.2,10.0.0.3".
function client_ip() {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $trusted = array_filter(array_map('trim', explode(',', (string)(getenv('LULLWIRE_TRUSTED_PROXIES') ?: getenv('HUSH_TRUSTED_PROXIES') ?: (defined('LULLWIRE_TRUSTED_PROXIES') ? LULLWIRE_TRUSTED_PROXIES : (defined('HUSH_TRUSTED_PROXIES') ? HUSH_TRUSTED_PROXIES : ''))))));
    if (!preg_match('/^(127\.|::1$|::ffff:127\.)/', $remote) && !in_array($remote, $trusted, true)) return $remote;
    // Which header the proxy uses: X-Forwarded-For (default) or e.g. CF-Connecting-IP.
    // Only the chosen one is read, so clients can't pick a header the proxy passes through.
    $hdr = strtoupper(str_replace('-', '_', (string)(getenv('LULLWIRE_FORWARDED_HEADER') ?: getenv('HUSH_FORWARDED_HEADER') ?: (defined('LULLWIRE_FORWARDED_HEADER') ? LULLWIRE_FORWARDED_HEADER : (defined('HUSH_FORWARDED_HEADER') ? HUSH_FORWARDED_HEADER : 'X-Forwarded-For')))));
    if ($hdr !== 'X_FORWARDED_FOR') {
        $v = trim((string)($_SERVER['HTTP_' . $hdr] ?? ''));
        return filter_var($v, FILTER_VALIDATE_IP) ? $v : $remote;
    }
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if (is_string($xff) && $xff !== '') {
        $last = trim(substr(strrchr(',' . $xff, ','), 1)); // the hop our proxy added
        if (filter_var($last, FILTER_VALIDATE_IP)) return $last;
    }
    return $remote;
}
// The client IP is hashed with a daily salt; nothing identifying is stored.
function client_key() {
    static $k = null;
    if ($k === null) {
        $saltf = LIMITS . '/salt-' . gmdate('Ymd');
        if (!is_file($saltf)) { @file_put_contents($saltf, bin2hex(random_bytes(16)), LOCK_EX); }
        $k = substr(hash('sha256', (@file_get_contents($saltf) ?: 'x') . client_ip()), 0, 24);
    }
    return $k;
}
// Fixed-window counter per client. Returns false once $max is exceeded.
function rate($name, $window, $max) {
    $f = LIMITS . '/' . $name . '-' . client_key() . '-' . intdiv(time(), $window);
    $h = @fopen($f, 'c+');
    if (!$h) return true;
    flock($h, LOCK_EX);
    $n = (int)stream_get_contents($h) + 1;
    ftruncate($h, 0); rewind($h); fwrite($h, (string)$n);
    flock($h, LOCK_UN); fclose($h);
    return $n <= $max;
}
function disk_ok() {
    $free = @disk_free_space(DATA);
    return $free === false || $free > MIN_FREE;
}
function sweep() {
    $now = time();
    foreach (glob(DATA . '/*', GLOB_ONLYDIR) ?: [] as $d) {
        if ($d === RECOVER || $d === LIMITS) continue;
        foreach (array_merge(glob($d . '/*.m') ?: [], glob($d . '/*.tmp') ?: []) as $f) {
            $age = $now - (int)@filemtime($f);
            if ($age > TTL || (substr($f, -4) === '.tmp' && $age > 600)) @unlink($f);
        }
        @rmdir($d); // only succeeds when empty
    }
    foreach (glob(RECOVER . '/*') ?: [] as $f) {
        if ($now - (int)@filemtime($f) > (substr($f, -4) === '.tmp' ? 600 : SLOT_TTL)) @unlink($f);
    }
    foreach (glob(LIMITS . '/*') ?: [] as $f) {
        if ($now - (int)@filemtime($f) > 172800) @unlink($f);
    }
}

// --- refuse to run with the data folder exposed -----------------------------
// Resolve the data folder itself (following symlinks when it exists) and refuse if it
// is, or is inside, the app folder or the document root. Nothing is created first.
$software = $_SERVER['SERVER_SOFTWARE'] ?? '';
$dataReal = rtrim(realpath(DATA) ?: (realpath(dirname(DATA)) ?: dirname(DATA)) . '/' . basename(DATA), '/') . '/';
$appReal = rtrim(realpath(__DIR__), '/') . '/';
$docRoot = realpath((string)($_SERVER['DOCUMENT_ROOT'] ?? '')) ?: null;
$insideWebRoot = strpos($dataReal, $appReal) === 0 || ($docRoot && $docRoot !== '/' && strpos($dataReal, rtrim($docRoot, '/') . '/') === 0);
if ($insideWebRoot && !preg_match('/Apache|LiteSpeed/i', $software) && !getenv('LULLWIRE_ROUTER')) {
    fail(500, 'data folder is inside the web root on a server that ignores .htaccess; set LULLWIRE_DATA (see docs/SELF-HOSTING.md)');
}

foreach ([DATA, RECOVER, LIMITS] as $d) if (!is_dir($d)) @mkdir($d, 0700, true);
if (!is_file(DATA . '/.htaccess')) {
    @file_put_contents(DATA . '/.htaccess',
        "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n" .
        "<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
}
if (mt_rand(1, 200) === 1) sweep();

$a = is_string($_GET['a'] ?? null) ? $_GET['a'] : '';

// --- deliver a blob to someone's box ---------------------------------------
// "send" carries the mailbox as the first 32 bytes of the body instead of in the URL,
// because request lines end up in access logs and bodies don't. "put" is the LEGACY
// form (apps before 0.6.1) with ?box= in the URL.
if ($a === 'put' || $a === 'send') {
    if ($a === 'send') {
        if (isset($_GET['box'])) fail(400, 'bad box');
        $raw = file_get_contents('php://input', false, null, 0, 32 + MAX_BLOB + 1);
        $box = $raw === false ? null : hexval(substr($raw, 0, 32), 32);
        $body = $raw === false ? false : (string)substr($raw, 32);
    } else {
        $box = hexval($_GET['box'] ?? null, 32);
        $body = null;
    }
    if ($box === null) fail(400, 'bad box');
    if (!rate('put', 60, PUTS_PER_MIN)) fail(429, 'slow down');
    if (!disk_ok()) fail(507, 'relay storage full');
    if ($body === null) $body = file_get_contents('php://input', false, null, 0, MAX_BLOB + 1);
    if ($body === false || strlen($body) < MIN_BLOB || strlen($body) > MAX_BLOB) fail(413, 'bad size');
    $dir = DATA . '/' . $box;
    if (!is_dir($dir)) @mkdir($dir, 0700);
    $files = glob($dir . '/*.m') ?: [];
    if (count($files) >= MAX_PER_BOX) fail(429, 'box full');
    $bytes = 0; foreach ($files as $f) $bytes += (int)@filesize($f);
    if ($bytes + strlen($body) > MAX_BOX_BYTES) fail(429, 'box full');
    $id = sprintf('%010d', time()) . bin2hex(random_bytes(6));
    file_put_contents("$dir/$id.tmp", $body);
    rename("$dir/$id.tmp", "$dir/$id.m");
    ok();
}

// --- recovery slots -----------------------------------------------------------
if ($a === 'rput' || $a === 'rget' || $a === 'rdel') {
    $in = body(MAX_SLOT + 4096);
    $l = hexarg($in, 'l', 32);
    $f = RECOVER . "/$l.json";
    if ($a === 'rget') {
        if (!is_file($f)) { usleep(random_int(50000, 150000)); fail(404, 'none'); }
        $rec = json_decode((string)file_get_contents($f), true);
        @touch($f);
        ok(['d' => $rec['d'] ?? '']);
    }
    $t = hash('sha256', hexarg($in, 't', 64));
    $exists = is_file($f);
    if ($exists) {
        $rec = json_decode((string)file_get_contents($f), true);
        if (!hash_equals((string)($rec['h'] ?? ''), $t)) fail(403, 'wrong token');
    }
    if ($a === 'rdel') { @unlink($f); ok(); }
    $d = $in['d'] ?? '';
    if (!is_string($d) || strlen($d) > MAX_SLOT || !preg_match('/^[A-Za-z0-9_-]+$/D', $d)) fail(400, 'bad data');
    if (!$exists && !rate('slot', 86400, SLOTS_PER_DAY)) fail(429, 'too many new slots today');
    if (!disk_ok()) fail(507, 'relay storage full');
    file_put_contents("$f.tmp", json_encode(['h' => $t, 'd' => $d]));
    rename("$f.tmp", $f);
    ok();
}

// --- owner actions: secret travels in the POST body, never in the URL ------
$in = body(16384);
$s = hexarg($in, 's', 64);
$dir = DATA . '/' . substr(hash('sha256', $s), 0, 32);

if ($a === 'get') {
    $wait = max(0, min(MAX_WAIT, (int)(is_string($_GET['wait'] ?? null) ? $_GET['wait'] : 0)));
    // Cap concurrent live requests per client so nobody can tie up every worker.
    $slot = null;
    if ($wait > 0) {
        for ($i = 0; $i < LIVE_PER_IP && !$slot; $i++) {
            $h = @fopen(LIMITS . '/live-' . client_key() . '-' . $i, 'c');
            if ($h && flock($h, LOCK_EX | LOCK_NB)) $slot = $h; elseif ($h) fclose($h);
        }
        if (!$slot) { // too many live connections from this client: tell it to back off
            header('Retry-After: 3');
            fail(429, 'too many live connections');
        }
    }
    // An empty, never-used mailbox: answer after a short pause instead of holding a worker.
    if (!is_dir($dir)) $wait = min($wait, 3);
    @set_time_limit($wait + 15);
    $end = microtime(true) + $wait;
    while (true) {
        $files = glob($dir . '/*.m') ?: [];
        if ($files || microtime(true) >= $end || connection_aborted()) break;
        usleep(400000);
    }
    $out = [];
    foreach ($files as $f) {
        $data = @file_get_contents($f);
        if ($data === false) continue;
        $out[] = ['id' => basename($f, '.m'), 'd' => base64_encode($data)];
        if (count($out) >= 100) break;
    }
    ok($out);
}

if ($a === 'ack') {
    $ids = is_array($in['ids'] ?? null) ? $in['ids'] : [];
    foreach (array_slice($ids, 0, 200) as $id) {
        if (hexval($id, 22) !== null) @unlink("$dir/$id.m");
    }
    ok();
}

fail(400, 'bad action');
