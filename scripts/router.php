<?php
// Router for PHP's built-in server (php -S), used by scripts/serve.sh.
// The built-in server ignores .htaccess, so this router:
//   - keeps the relay's data folder and dotfiles private,
//   - lets only relay.php execute,
//   - serves static files itself so every page carries anti-framing headers.
// Not needed on Apache/cPanel (web/.htaccess does the same there).
//
// Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

$web  = realpath(__DIR__ . '/../web');
$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');

function deny() { http_response_code(404); header('Content-Type: text/plain'); echo "Not found\n"; return true; }

if (preg_match('#(^|/)(data|\.)#', $path)) return deny();          // data dir and dotfiles

if (preg_match('#/relay\.php$#', $path)) {
    putenv('LULLWIRE_ROUTER=1'); // this router keeps the data folder private
    require $web . '/relay.php';
    return true;
}

if (substr($path, -1) === '/') $path .= 'index.html';
$file = realpath($web . $path);
if ($file === false || strpos($file, $web . DIRECTORY_SEPARATOR) !== 0 || !is_file($file)) return deny();
if (preg_match('#\.(php|go)$#', $file)) return deny();               // no other code is executed or served

$types = [
    'html' => 'text/html; charset=utf-8', 'js' => 'text/javascript; charset=utf-8',
    'json' => 'application/json', 'svg' => 'image/svg+xml', 'png' => 'image/png',
    'css' => 'text/css; charset=utf-8', 'txt' => 'text/plain; charset=utf-8', 'ico' => 'image/x-icon',
];
$ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
header('Content-Type: ' . ($types[$ext] ?? 'application/octet-stream'));
header("Content-Security-Policy: frame-ancestors 'none'");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-cache');
header('Content-Length: ' . filesize($file));
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') readfile($file);
return true;
