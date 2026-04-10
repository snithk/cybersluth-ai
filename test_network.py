"""
Quick test — run this in CMD to check if live network capture works on your machine.

Usage:
    python test_network.py
"""
import time

print("=" * 50)
print("  LIVE NETWORK CAPTURE TEST")
print("=" * 50)

# Step 1: Check psutil
try:
    import psutil
    print("\n[1] psutil installed         : YES")
except ImportError:
    print("\n[1] psutil installed         : NO  <-- run: pip install psutil")
    exit()

# Step 2: Check bytes/packets (no admin needed)
try:
    io = psutil.net_io_counters()
    print(f"[2] Bytes Sent               : {io.bytes_sent:,}")
    print(f"    Bytes Received           : {io.bytes_recv:,}")
    print(f"    Packets Sent             : {io.packets_sent:,}")
    print(f"    Packets Recv             : {io.packets_recv:,}")
    print("    >> Traffic data OK       : YES")
except Exception as e:
    print(f"    >> Traffic data OK       : NO  ({e})")

# Step 3: Check live update (wait 2 seconds, see if numbers change)
print("\n[3] Watching for live changes (2 seconds)...")
io1 = psutil.net_io_counters()
time.sleep(2)
io2 = psutil.net_io_counters()
sent_diff = io2.bytes_sent - io1.bytes_sent
recv_diff = io2.bytes_recv - io1.bytes_recv
print(f"    New bytes sent in 2s      : +{sent_diff:,}")
print(f"    New bytes recv in 2s      : +{recv_diff:,}")
if sent_diff > 0 or recv_diff > 0:
    print("    >> Live traffic detected  : YES ✅")
else:
    print("    >> Live traffic detected  : NO (no network activity in 2s, try browsing)")

# Step 4: Check connections (needs admin on Windows)
print("\n[4] Checking active connections...")
try:
    conns = psutil.net_connections(kind='inet')
    active = [c for c in conns if c.laddr and c.raddr]
    print(f"    Active connections found : {len(active)}")
    for c in active[:5]:
        try:
            proc = psutil.Process(c.pid).name() if c.pid else "Unknown"
        except:
            proc = "Unknown"
        print(f"      {proc:20s} {c.laddr.ip}:{c.laddr.port} --> {c.raddr.ip}:{c.raddr.port}")
    print("    >> Connections OK        : YES ✅")
except psutil.AccessDenied:
    print("    >> Connections OK        : NO  ❌")
    print("       REASON: Need to run CMD as Administrator")
    print("       Right-click CMD -> 'Run as administrator' -> run again")
except Exception as e:
    print(f"    >> Connections OK        : NO  ({e})")

print("\n" + "=" * 50)
print("  Run 'python src\\app.py' to start the dashboard")
print("  Then open: http://localhost:5000")
print("=" * 50)
