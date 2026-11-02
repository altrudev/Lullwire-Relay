// Lullwire Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev)
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// "lullwire-relay init": a few questions, then a settings file and the exact next
// steps for the way people will reach the relay. Answers can be piped in; an empty
// answer (or end of input) takes the default shown in brackets.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type initAnswers struct {
	reach   string // proxy, tunnel, onion, local
	domain  string
	data    string
	port    int
	private bool
	path    string
	code    string
}

func runInit(in io.Reader, out io.Writer, args []string) error {
	target, _ := configArg(args)
	if target == "" {
		target = defaultConfigPath()
	}
	if target == "" {
		return errors.New("no settings folder on this system; use: lullwire-relay init -config /path/relay.conf")
	}
	br := bufio.NewReader(in)
	eof := false
	read := func() string {
		line, err := br.ReadString('\n')
		if err != nil {
			eof = true
			fmt.Fprintln(out)
		}
		return strings.TrimSpace(line)
	}
	ask := func(q, def string) string {
		if def != "" {
			fmt.Fprintf(out, "%s [%s]: ", q, def)
		} else {
			fmt.Fprintf(out, "%s: ", q)
		}
		if v := read(); v != "" {
			return v
		}
		return def
	}
	yes := func(q string, def bool) bool {
		d := "Y/n"
		if !def {
			d = "y/N"
		}
		fmt.Fprintf(out, "%s [%s]: ", q, d)
		v := strings.ToLower(read())
		if v == "" {
			return def
		}
		return strings.HasPrefix(v, "y")
	}

	fmt.Fprintf(out, "Lullwire Relay %s setup. Press Enter to accept the answer in [brackets].\n\n", version)
	fmt.Fprintln(out, "How will people reach this relay?")
	fmt.Fprintln(out, "  1  my own domain, through Caddy or nginx (HTTPS)")
	fmt.Fprintln(out, "  2  Cloudflare Tunnel (no open ports; works on a phone or behind a home router)")
	fmt.Fprintln(out, "  3  Tor onion service")
	fmt.Fprintln(out, "  4  just testing on this computer")
	var a initAnswers
	switch ask("Choose 1-4", "1") {
	case "2":
		a.reach = "tunnel"
	case "3":
		a.reach = "onion"
	case "4":
		a.reach = "local"
	default:
		a.reach = "proxy"
	}
	if a.reach == "proxy" || a.reach == "tunnel" {
		for {
			d := strings.ToLower(strings.Trim(ask("Domain name people will use, e.g. chat.example.com", ""), "/ "))
			d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
			if d != "" && !strings.ContainsAny(d, " /:@") && strings.Contains(d, ".") {
				a.domain = d
				break
			}
			if eof { // answers were piped in and ran out: leave a placeholder to edit
				a.domain = "chat.example.com"
				break
			}
			fmt.Fprintln(out, "  Enter just the name, like chat.example.com.")
		}
	}
	a.data = ask("Data folder", defaultDataDir())
	for {
		p, err := strconv.Atoi(ask("Local port", "8080"))
		if err == nil && p > 0 && p < 65536 {
			a.port = p
			break
		}
		if eof {
			a.port = 8080
			break
		}
		fmt.Fprintln(out, "  A number from 1 to 65535.")
	}
	if a.reach != "local" {
		fmt.Fprintln(out, "\nA private relay looks like an ordinary small website: the app lives under a secret")
		fmt.Fprintln(out, "path, and only people with your join code (it travels inside your invites) can use it.")
		a.private = yes("Make it private (recommended)?", true)
		if a.private {
			a.path, a.code = "/"+randWord(10)+"/", randWord(16)
		}
	}

	if _, err := os.Stat(target); err == nil && !yes("\n"+target+" exists. Replace it?", false) {
		return errors.New("nothing written")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Lullwire Relay settings, written by \"lullwire-relay init\" (%s).\n", a.reach)
	fmt.Fprintf(&b, "# Flags and LULLWIRE_* environment variables override these.\n")
	fmt.Fprintf(&b, "addr = %s\n", net.JoinHostPort("127.0.0.1", strconv.Itoa(a.port)))
	fmt.Fprintf(&b, "data = %s\n", strconv.Quote(a.data))
	if a.reach == "onion" {
		fmt.Fprintf(&b, "onion = true\n")
	}
	if a.reach == "tunnel" {
		fmt.Fprintf(&b, "forwarded-header = CF-Connecting-IP\n")
	}
	if a.private {
		fmt.Fprintf(&b, "path = %s\njoin-code = %s\n", a.path, a.code)
	}
	if err := os.WriteFile(target, []byte(b.String()), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nSaved %s\n", target)
	printNextSteps(out, a, target)
	return nil
}

func printNextSteps(out io.Writer, a initAnswers, conf string) {
	local := fmt.Sprintf("127.0.0.1:%d", a.port)
	app := "https://" + a.domain + a.path
	if a.path == "" {
		app = "https://" + a.domain + "/"
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "lullwire-relay"
	}
	fmt.Fprintf(out, "\nStart it:\n\n    %s\n", exe)
	switch a.reach {
	case "local":
		fmt.Fprintf(out, "\nThen open http://localhost:%d/ in a browser on this computer.\n", a.port)
		return
	case "proxy":
		fmt.Fprintf(out, "\nCaddy (gets an HTTPS certificate by itself; passes calls and live mail through):\n\n")
		fmt.Fprintf(out, "    %s {\n        reverse_proxy %s\n    }\n", a.domain, local)
		fmt.Fprintf(out, "\nnginx (inside your HTTPS server block; the Upgrade lines carry calls and live mail):\n\n")
		fmt.Fprintf(out, "    location / {\n        proxy_pass http://%s;\n        proxy_http_version 1.1;\n", local)
		fmt.Fprintf(out, "        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n")
		fmt.Fprintf(out, "        proxy_set_header X-Forwarded-For $remote_addr;\n        proxy_read_timeout 120s;\n    }\n")
	case "tunnel":
		fmt.Fprintf(out, "\nCloudflare Tunnel:\n\n    cloudflared tunnel login\n    cloudflared tunnel create lullwire\n")
		fmt.Fprintf(out, "    cloudflared tunnel route dns lullwire %s\n    cloudflared tunnel run --url http://%s lullwire\n", a.domain, local)
	case "onion":
		fmt.Fprintf(out, "\nTor: add to /etc/tor/torrc, restart Tor, and read your address:\n\n")
		fmt.Fprintf(out, "    HiddenServiceDir /var/lib/tor/lullwire/\n    HiddenServicePort 80 %s\n\n", local)
		fmt.Fprintf(out, "    sudo cat /var/lib/tor/lullwire/hostname\n")
		fmt.Fprintf(out, "\nBack up /var/lib/tor/lullwire/: it holds the address's private key.\n")
		app = "http://<your address>.onion" + a.path
		if a.path == "" {
			app = "http://<your address>.onion/"
		}
	}
	fmt.Fprintf(out, "\nTo keep it running (Linux, systemd), save as /etc/systemd/system/lullwire-relay.service:\n\n")
	fmt.Fprintf(out, "    [Unit]\n    Description=Lullwire Relay\n    After=network-online.target\n\n    [Service]\n")
	fmt.Fprintf(out, "    ExecStart=%s -config %s\n    User=%s\n    Restart=on-failure\n    NoNewPrivileges=true\n", exe, conf, currentUser())
	fmt.Fprintf(out, "    ProtectSystem=strict\n    ProtectHome=read-only\n    ReadWritePaths=%s\n    PrivateTmp=true\n\n", a.data)
	fmt.Fprintf(out, "    [Install]\n    WantedBy=multi-user.target\n\n    sudo systemctl enable --now lullwire-relay\n")
	fmt.Fprintf(out, "\nThen open %s , create your profile and share invites from there.\n", app)
	if a.private {
		fmt.Fprintf(out, "Your join code is %s. You never need to hand it out: your invites carry it.\n", a.code)
	}
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "lullwire"
}
