# dropit

AirDrop-style file transfer between two computers on the same Wi-Fi. One shell script, runs on a Raspberry Pi (DietPi/Linux) and on a Mac. Needs only `python3`. No installs, no admin rights, no router changes.

## How it works

- The receiving device shows a random 6-digit PIN.
- The sending device finds it automatically (UDP broadcast on the local network), you type the PIN, and you are paired.
- The receiver confirms each file with y/n. Progress bar and a SHA-256 check on every file.
- Transfers work in both directions: run "receive" on one device and "send" on the other, then swap.
- Everything stays on the local network. Data is encrypted and authenticated with a key derived from the PIN (PBKDF2, SHA-256 stream, HMAC per message). Three wrong PINs make a new one.

## Install and run

Pi (DietPi window, root@DietPi):

```
wget -O dropit.sh https://raw.githubusercontent.com/Greenisus1/dropit/main/dropit.sh
sh dropit.sh
```

Mac (Terminal window), from a folder you can read, for example ~/CrunchByte:

```
cd ~/CrunchByte
```

macOS has no wget, so either copy the file from the Pi (run on the Mac, use the Pi's IP from `hostname -I`):

```
scp -O root@PI_IP:/root/dropit.sh ~/CrunchByte/
```

or download it with curl:

```
curl -o dropit.sh https://raw.githubusercontent.com/Greenisus1/dropit/main/dropit.sh
```

Then run it:

```
sh dropit.sh
```

Pick 1 (receive) on one device and 2 (send) on the other. The receiver shows a PIN, the sender chooses it from the list and types the PIN. Or skip the menu:

```
sh dropit.sh receive
sh dropit.sh send
sh dropit.sh send photo.jpg
```

Received files go to `~/Downloads` on a Mac and `~/Dropit` on Linux (or `~/Dropit` if Downloads is not writable).

## Notes

- Both devices must be on the same Wi-Fi. Guest or school networks often block device-to-device traffic.
- On a Mac, click Allow if it asks about incoming network connections for python3.
- If macOS blocks reading a file in Downloads, copy it to another folder first.
- Ports used: UDP 48555 (discovery), TCP 48556 (transfer).
- Home-made crypto from standard library parts, fine for a home network, not a replacement for audited tools. A 6-digit PIN can be guessed offline by someone who records the pairing on your network.
