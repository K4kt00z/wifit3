# TKIP injection (Beck-Tews)

Recovers a live TKIP network's per-packet keystream and Michael MIC key from a
single captured frame, without the passphrase, then hands the operator a
bounded injection capability (default payload: a spoofed ARP reply).

## What it attacks

- **WPA1-TKIP** networks, and
- **mixed WPA/WPA2 networks whose group cipher is downgraded to TKIP** even
  when the pairwise cipher is CCMP — broadcast/multicast traffic on those
  networks is still TKIP-protected.

It needs WMM/QoS negotiated (the TID replay-counter bypass) and at least one
associated client (the ARP source, and the only thing that can emit the
MIC-failure oracle). `precheck.assess()` reports what it can see up front;
whether the AP's rekey interval is long enough is only discovered by the walk
itself.

## How it works

1. **Deauth** the target's client to provoke a fresh ARP.
2. **Capture** the AP's TKIP-encrypted reply to that client (or, on the
   group-downgrade path, its next broadcast frame).
3. **Chop** it byte-by-byte (`TkipChop`): each guess is injected and the
   target client's Michael MIC-failure report (sniffed off the air) is the
   oracle. A wrong guess is silently dropped — free. A correct guess costs a
   countermeasure-interval wait (the AP tears down for ~60s after two
   failures) before the next byte.
4. If a real 4-way-handshake message is seen mid-walk, the AP has rekeyed:
   the walk aborts with that reason instead of spinning for the rest of the
   run.
5. On success, the recovered keystream + Michael key are held on the
   campaign (`TkipInject.recovered`) for the operator to spend as injected
   frames (`inject.forge_tkip_frame`) — a later feature surfaces this in the
   UI.

## What it is not

Not passphrase recovery, not full traffic decryption, and not an unlimited
channel: the recovered keystream only covers the one captured frame's length,
and the Michael key dies at the next rekey. Treat a successful run as a short
injection window, not a persistent foothold.
