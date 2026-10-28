# Simulates a nosy desktop app for the live tests: resolves via the OS resolver (like Spotify/Zoom),
# contacts a few trackers, then beacons to example.com every ~6s.
import socket
import time


def hit(host, hold=2.5):
    try:
        s = socket.create_connection((host, 443), timeout=5)
        time.sleep(hold)
        s.close()
    except OSError as e:
        print("probe fail", host, e)


for h in ["www.google-analytics.com", "stats.g.doubleclick.net", "sb.scorecardresearch.com",
          "www.googletagmanager.com", "cdn.segment.com", "api.mixpanel.com", "github.com"]:
    hit(h)
for _ in range(6):
    t = time.time()
    hit("example.com")
    time.sleep(max(0, 6 - (time.time() - t)))
