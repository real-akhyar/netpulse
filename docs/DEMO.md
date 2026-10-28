# Demo recipe (Windows 11 demo machine)

netpulse names trackers by reading the **Windows DNS cache** — the hostname each app actually
looked up (`google-analytics.com`), which reverse-DNS can't recover (it returns `*.1e100.net`).
Apps that use the normal Windows resolver (Spotify, Zoom, Teams, Office, VS Code, Python, most
desktop apps) work out of the box. **Browsers need setup**, because by default they bypass the
Windows cache:

- **Chrome/Edge built-in DNS client** resolves names itself (seen during Phase 1: Chromium talking
  straight to `1.1.1.1:53`), so its lookups never reach the Windows cache.
- **Secure DNS (DoH)** sends lookups over HTTPS — same problem. With Cloudflare/Google set as the
  DNS server, Chrome/Edge auto-upgrade to DoH even when "Secure DNS" looks unset.
- **QUIC (HTTP/3)** runs over UDP, and Windows doesn't report UDP remote addresses — those
  connections are invisible to netpulse.

## Option A — demo in Chrome or Edge (registry policy, needs admin, one-time)

Run in an **admin** PowerShell, then fully quit and reopen the browser:

```powershell
# Chrome
New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name BuiltInDnsClientEnabled -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name DnsOverHttpsMode -Type String -Value "off"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name QuicAllowed -Type DWord -Value 0

# Edge
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BuiltInDnsClientEnabled -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name DnsOverHttpsMode -Type String -Value "off"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name QuicAllowed -Type DWord -Value 0
```

Verify at `chrome://policy` / `edge://policy` (click **Reload policies**): all three show `OK`.
The browser will say "Managed by your organization" — expected.

**Undo after the demo:**

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name BuiltInDnsClientEnabled,DnsOverHttpsMode,QuicAllowed
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name BuiltInDnsClientEnabled,DnsOverHttpsMode,QuicAllowed
```

## Option B — demo in Firefox (no admin, no registry)

Firefox uses the Windows resolver unless DoH is on.

1. Settings → Privacy & Security → **DNS over HTTPS** → **Off**.
2. `about:config` → `network.http.http3.enable` → **false** (disables QUIC).
3. Restart Firefox.

(Firefox is not installed on the dev machine — install it on the demo machine if using this option.)

## Pre-flight (2 minutes before recording)

1. Apply Option A or B.
2. Have **Spotify** and/or **Zoom** installed (non-browser apps — they populate the cache with no setup).
3. Start `netpulse watch` **before** opening the apps, so their first connections are caught.
4. Load an ad-supported news site (e.g. theguardian.com, cnn.com), then confirm the browser now
   feeds the cache:
   ```powershell
   ipconfig /displaydns | findstr /i "google-analytics doubleclick googletagmanager"
   ```
   If nothing prints, the browser is still bypassing the cache — recheck the policy page / restart.
5. Within ~10s the Caught panel should name the browser with tracker domains.
