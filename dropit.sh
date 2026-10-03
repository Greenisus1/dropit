#!/bin/sh
# dropit.sh - AirDrop-style file transfer over your home Wi-Fi.
# Works on the Pi (DietPi) and on a Mac. Needs only python3. No admin, no installs.
# Run:  sh dropit.sh        (menu: receive or send)
#       sh dropit.sh receive
#       sh dropit.sh send [file ...]
command -v python3 >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }
T=$(mktemp "${TMPDIR:-/tmp}/dropit.XXXXXX") || exit 1
trap 'rm -f "$T"' EXIT INT TERM
sed '1,/^#PYTHON-BELOW$/d' "$0" > "$T"
python3 -u "$T" "$@"
exit $?
#PYTHON-BELOW
import os, sys, socket, struct, json, time, hmac, hashlib, secrets, threading, platform

DPORT = 48555          # UDP discovery
TPORT = 48556          # TCP transfer
MAGIC = b"DROPIT1"
CHUNK = 65536
NAME = socket.gethostname().split(".")[0]


def recvn(s, n):
    b = bytearray()
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d:
            raise ConnectionError("connection closed")
        b += d
    return bytes(b)


def xor(data, ks):
    n = len(data)
    return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(n, "big") if n else b""


class Chan:
    """Encrypted + authenticated channel. Key comes from the PIN."""
    def __init__(self, sock, key, role):
        self.s = sock
        self.ek, self.mk = key[:32], key[32:]
        self.role = role  # b"C" or b"S"
        self.send_seq = 0
        self.recv_seq = 0

    def _ks(self, who, seq, n):
        return hashlib.shake_256(self.ek + who + struct.pack(">Q", seq)).digest(n)

    def send(self, data):
        ct = xor(data, self._ks(self.role, self.send_seq, len(data)))
        hdr = struct.pack(">I", len(ct))
        mac = hmac.new(self.mk, self.role + struct.pack(">Q", self.send_seq) + hdr + ct, hashlib.sha256).digest()
        self.s.sendall(hdr + ct + mac)
        self.send_seq += 1

    def recv(self):
        other = b"S" if self.role == b"C" else b"C"
        hdr = recvn(self.s, 4)
        n = struct.unpack(">I", hdr)[0]
        if n > CHUNK * 4:
            raise ValueError("bad frame")
        ct = recvn(self.s, n)
        mac = recvn(self.s, 32)
        good = hmac.new(self.mk, other + struct.pack(">Q", self.recv_seq) + hdr + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, good):
            raise ValueError("authentication failed")
        pt = xor(ct, self._ks(other, self.recv_seq, n))
        self.recv_seq += 1
        return pt


def derive(pin, cn, sn):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), MAGIC + cn + sn, 20000, 64)


def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%.1f %s" % (n, u) if u != "B" else "%d B" % n
        n /= 1024.0


def bar(done, total, t0):
    el = max(time.time() - t0, 0.001)
    pct = 100 if total == 0 else int(done * 100 / total)
    w = 24
    f = int(w * pct / 100)
    sys.stdout.write("\r  [%s%s] %3d%%  %s / %s  %s/s   " % ("#" * f, "-" * (w - f), pct, human(done), human(total), human(done / el)))
    sys.stdout.flush()


def local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for i in socket.gethostbyname_ex(socket.gethostname())[2]:
            ips.add(i)
    except Exception:
        pass
    return [i for i in ips if not i.startswith("127.")]


def save_dir():
    home = os.path.expanduser("~")
    cands = []
    if platform.system() == "Darwin":
        cands.append(os.path.join(home, "Downloads"))
    cands.append(os.path.join(home, "Dropit"))
    for d in cands:
        try:
            os.makedirs(d, exist_ok=True)
            t = os.path.join(d, ".dropit-test")
            open(t, "w").close()
            os.remove(t)
            return d
        except Exception:
            continue
    return os.getcwd()


def unique(d, name):
    name = os.path.basename(name.replace("\\", "/")) or "file"
    if name.startswith("."):
        name = "_" + name
    p = os.path.join(d, name)
    base, ext = os.path.splitext(name)
    i = 1
    while os.path.exists(p):
        p = os.path.join(d, "%s-%d%s" % (base, i, ext))
        i += 1
    return p


# ---------------- receive ----------------

def new_pin():
    return "%06d" % secrets.randbelow(1000000)


def beacon_loop(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    s.bind(("", DPORT))
    s.settimeout(1)
    reply = json.dumps({"app": "dropit", "name": NAME, "port": TPORT}).encode()
    while not stop.is_set():
        try:
            d, a = s.recvfrom(256)
        except socket.timeout:
            continue
        except Exception:
            continue
        if d.startswith(b"DROPIT?"):
            try:
                s.sendto(reply, a)
            except Exception:
                pass


def handle(conn, addr, pin, dest):
    conn.settimeout(60)
    if recvn(conn, 7) != MAGIC:
        return "bad"
    cn = recvn(conn, 16)
    sn = secrets.token_bytes(16)
    conn.sendall(sn)
    key = derive(pin, cn, sn)
    proof = recvn(conn, 32)
    good = hmac.new(key[32:], b"C" + cn + sn, hashlib.sha256).digest()
    if not hmac.compare_digest(proof, good):
        conn.sendall(b"\x00" * 32)
        return "badpin"
    conn.sendall(hmac.new(key[32:], b"S" + cn + sn, hashlib.sha256).digest())
    ch = Chan(conn, key, b"S")
    while True:
        try:
            hdr = json.loads(ch.recv().decode())
        except ConnectionError:
            return "ok"
        if hdr.get("type") == "bye":
            return "ok"
        name, size = hdr["name"], int(hdr["size"])
        print("\n  Incoming: %s (%s) from %s" % (os.path.basename(name), human(size), addr[0]))
        conn.settimeout(None)
        ans = input("  Accept? (y/n) ").strip().lower()
        conn.settimeout(60)
        if ans not in ("y", "yes"):
            ch.send(json.dumps({"ok": False}).encode())
            print("  Declined.")
            continue
        path = unique(dest, name)
        ch.send(json.dumps({"ok": True}).encode())
        h = hashlib.sha256()
        got = 0
        t0 = time.time()
        try:
            with open(path, "wb") as f:
                while got < size:
                    b = ch.recv()
                    f.write(b)
                    h.update(b)
                    got += len(b)
                    bar(got, size, t0)
            fin = json.loads(ch.recv().decode())
        except Exception as e:
            print("\n  Transfer failed: %s" % e)
            try:
                os.remove(path)
            except Exception:
                pass
            raise
        okh = fin.get("sha256") == h.hexdigest() and got == size
        ch.send(json.dumps({"ok": okh}).encode())
        print("\n  Saved: %s%s" % (path, "" if okh else "  (CHECK FAILED)"))


def receive():
    dest = save_dir()
    pin = new_pin()
    stop = threading.Event()
    threading.Thread(target=beacon_loop, args=(stop,), daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", TPORT))
    srv.listen(2)
    fails = 0
    while True:
        print("")
        print("  Receiving as: %s   (%s)" % (NAME, ", ".join(local_ips()) or "no network?"))
        print("  Files save to: %s" % dest)
        print("  +--------------------+")
        print("  |    PIN: %s    |" % pin)
        print("  +--------------------+")
        print("  Type this PIN on the sending device. Ctrl+C to stop.")
        while True:
            try:
                conn, addr = srv.accept()
            except KeyboardInterrupt:
                print("\n  Stopped.")
                stop.set()
                return 0
            try:
                r = handle(conn, addr, pin, dest)
            except KeyboardInterrupt:
                print("\n  Stopped.")
                stop.set()
                return 0
            except Exception as e:
                r = "err"
                if not isinstance(e, (ConnectionError, socket.timeout, OSError, ValueError)):
                    print("  Error: %s" % e)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            if r == "badpin":
                fails += 1
                print("\n  Wrong PIN from %s (%d/3)" % (addr[0], fails))
                if fails >= 3:
                    pin = new_pin()
                    fails = 0
                    print("  Too many wrong PINs. New PIN made.")
                    break
            elif r == "ok":
                print("\n  Sender disconnected. Same PIN still works.")


# ---------------- send ----------------

def discover():
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(0.4)
    targets = ["255.255.255.255"]
    for ip in local_ips():
        p = ip.split(".")
        targets.append("%s.%s.%s.255" % (p[0], p[1], p[2]))
    end = time.time() + 3
    last = 0
    while time.time() < end:
        if time.time() - last > 0.8:
            for t in targets:
                try:
                    s.sendto(b"DROPIT?", (t, DPORT))
                except Exception:
                    pass
            last = time.time()
        try:
            d, a = s.recvfrom(512)
            j = json.loads(d.decode())
            if j.get("app") == "dropit":
                found[a[0]] = (j.get("name", a[0]), int(j.get("port", TPORT)))
        except Exception:
            pass
    return found


def connect(ip, port, pin):
    c = socket.create_connection((ip, port), timeout=10)
    cn = secrets.token_bytes(16)
    c.sendall(MAGIC + cn)
    sn = recvn(c, 16)
    key = derive(pin, cn, sn)
    c.sendall(hmac.new(key[32:], b"C" + cn + sn, hashlib.sha256).digest())
    back = recvn(c, 32)
    if not hmac.compare_digest(back, hmac.new(key[32:], b"S" + cn + sn, hashlib.sha256).digest()):
        c.close()
        return None
    c.settimeout(None)
    return Chan(c, key, b"C")


def send_file(ch, path):
    size = os.path.getsize(path)
    ch.send(json.dumps({"type": "file", "name": os.path.basename(path), "size": size}).encode())
    print("  Waiting for the other device to accept...")
    if not json.loads(ch.recv().decode()).get("ok"):
        print("  They declined.")
        return
    h = hashlib.sha256()
    sent = 0
    t0 = time.time()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            ch.send(b)
            h.update(b)
            sent += len(b)
            bar(sent, size, t0)
    if size == 0:
        bar(0, 0, t0)
    ch.send(json.dumps({"sha256": h.hexdigest()}).encode())
    r = json.loads(ch.recv().decode())
    print("\n  Sent OK, verified." if r.get("ok") else "\n  Sent, but the check FAILED.")


def clean_path(p):
    p = p.strip()
    if len(p) > 1 and p[0] == p[-1] and p[0] in "\"'":
        p = p[1:-1]
    p = p.replace("\\ ", " ")
    return os.path.expanduser(p)


def send(files):
    print("\n  Looking for devices on your Wi-Fi...")
    found = discover()
    while True:
        items = list(found.items())
        if items:
            print("  Found:")
            for i, (ip, (n, p)) in enumerate(items, 1):
                print("   %d) %s  (%s)" % (i, n, ip))
        else:
            print("  No devices found. Is the other one in receive mode on the same Wi-Fi?")
        print("   r) search again   m) type an IP address   q) quit")
        a = input("  Choose: ").strip().lower()
        if a == "q":
            return 0
        if a == "r":
            found = discover()
            continue
        if a == "m":
            ip = input("  IP address: ").strip()
            target = (ip, TPORT)
            break
        if a.isdigit() and 1 <= int(a) <= len(items):
            target = (items[int(a) - 1][0], items[int(a) - 1][1][1])
            break
    ch = None
    for _ in range(3):
        pin = input("  PIN shown on the other device: ").strip()
        try:
            ch = connect(target[0], target[1], pin)
        except Exception as e:
            print("  Could not connect: %s" % e)
            return 1
        if ch:
            break
        print("  Wrong PIN.")
        if _ == 2:
            return 1
    print("  Paired.")
    try:
        queue = list(files)
        while True:
            if not queue:
                p = input("\n  File to send (drag it here, or Enter to finish): ")
                if not p.strip():
                    break
                queue = [p]
            p = clean_path(queue.pop(0))
            if not os.path.isfile(p):
                print("  Not a file: %s" % p)
                continue
            try:
                send_file(ch, p)
            except PermissionError:
                print("  Can't read that file (macOS may block Downloads). Copy it to ~/CrunchByte first.")
        try:
            ch.send(json.dumps({"type": "bye"}).encode())
        except Exception:
            pass
    except (ConnectionError, ValueError) as e:
        print("\n  Connection lost: %s" % e)
        return 1
    return 0


def main():
    a = sys.argv[1:]
    try:
        if a and a[0] in ("receive", "r"):
            return receive()
        if a and a[0] in ("send", "s"):
            return send(a[1:])
        print("\n  dropit - send files between your devices over Wi-Fi")
        print("   1) Receive (show a PIN)")
        print("   2) Send")
        c = input("  Choose 1 or 2: ").strip()
        if c == "1":
            return receive()
        if c == "2":
            return send([])
    except (KeyboardInterrupt, EOFError):
        print("\n  Bye.")
    return 0


sys.exit(main())
