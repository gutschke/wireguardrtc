# Contributing to wireguardrtc

## Repository layout

| File / directory | Purpose |
|---|---|
| `wireguardrtc` | The daemon (single Python 3 asyncio file, ~1100 lines) |
| `wireguardrtc.conf` | Example global config (installed to `/etc/wireguardrtc/`) |
| `peers.d.example/` | Example per-peer drop-ins (installed to `/usr/share/doc/wireguardrtc/examples/`) |
| `wireguardrtc.service` | systemd unit |
| `wireguardrtc.8` | Man page (groff/troff source) |
| `wg-holepunch-guide.md` | Authoritative design doc — read this before making protocol changes |
| `build_docs.py` | Regenerates `wg-holepunch-guide.{html,pdf}`; never edit the outputs directly |
| `tests/` | Validation tests; see `tests/README.md` for which need root |
| `debian/` | Debian package build directory |
| `venv/` | Python 3 virtualenv (not committed; create with the steps below) |

## Prerequisites

### Runtime dependencies (installed automatically by the package)

The package declares `python3` and `python3-venv` as dependencies.
At install time, `postinst` creates `/var/lib/wireguardrtc/venv` and
runs `pip install -r /usr/lib/wireguardrtc/requirements.txt` into it.
This requires an internet connection during `dpkg -i` / `apt install`.

To run the daemon from source (outside the package), create a local venv:

```sh
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

### Build-only dependencies

```sh
# Debian / Ubuntu
sudo apt install debhelper devscripts fakeroot lintian
```

`fakeroot` lets `dpkg-buildpackage` simulate file ownership without actually
running as root. It is pulled in automatically by `devscripts` on most systems.

The package build itself requires **no internet access** — all Python
dependencies are installed at package install time, not build time.

## Day-to-day development checks

### Syntax-check the daemon

```sh
python3 -m py_compile wireguardrtc && echo "OK"
```

### Render and visually inspect the man page

```sh
# Plain-text (ASCII)
groff -t -man -Tascii wireguardrtc.8 | less

# PDF (requires groff with PDF output support)
groff -t -man -Tpdf wireguardrtc.8 > /tmp/wireguardrtc.pdf
```

### Rebuild HTML / PDF documentation

```sh
source venv/bin/activate
./build_docs.py
# Produces wg-holepunch-guide.html and wg-holepunch-guide.pdf
```

### Run the daemon from source (needs CAP_NET_ADMIN + CAP_NET_RAW)

```sh
export WIREGUARDRTC_CONFIG_DIR=$HOME/wg-test
mkdir -p $HOME/wg-test/peers.d
cp wireguardrtc.conf $HOME/wg-test/
# Edit $HOME/wg-test/wireguardrtc.conf — set a real Salt value
sudo venv/bin/python3 ./wireguardrtc --log-level DEBUG
```

The installed binary uses the system venv shebang
(`/var/lib/wireguardrtc/venv/bin/python3`), so from source you must
invoke it via the local venv or with an explicit interpreter.

To check the configuration without starting the daemon:

```sh
sudo wireguardrtc --show-config          # installed binary
sudo venv/bin/python3 ./wireguardrtc --show-config   # from source
```

## Building the Debian package

```sh
chmod +x wireguardrtc   # must be executable or dpkg installs it 0644
dpkg-buildpackage -us -uc -b
```

Flags: `-b` binary-only build, `-us`/`-uc` skip signing.

The `.deb`, `.buildinfo`, and `.changes` files land in the **parent directory**.

### Inspect the package

```sh
dpkg-deb --contents ../wireguardrtc_0.1.0-1_all.deb
dpkg-deb --info ../wireguardrtc_0.1.0-1_all.deb
```

### Lint the package

```sh
lintian --no-tag-display-limit ../wireguardrtc_0.1.0-1_all.deb
```

Expected warning: `no-upstream-changelog` (normal for native packages).

### Clean the build tree

```sh
dpkg-buildpackage --target=clean
```

## Installing for manual testing

```sh
sudo dpkg -i ../wireguardrtc_0.1.0-1_all.deb
sudo apt-get install -f   # if dependencies are missing
```

After install, configure before starting:

```sh
# 1. Generate a shared salt (use the SAME value on every participating host)
head -c 32 /dev/urandom | base64

# 2. Edit the global config
sudo nano /etc/wireguardrtc/wireguardrtc.conf

# 3. Add at least one peer drop-in
sudo cp /usr/share/doc/wireguardrtc/examples/peers.d/active-peer.conf \
        /etc/wireguardrtc/peers.d/my-peer.conf
sudo nano /etc/wireguardrtc/peers.d/my-peer.conf

# 4. Verify broker IDs match on both peers
sudo wireguardrtc --show-config

# 5. Start
sudo systemctl start wireguardrtc
journalctl -fu wireguardrtc
```

## Validation tests

See `tests/README.md` for the full table. Some tests require `sudo`.

```sh
./venv/bin/python tests/05_peerjs.py   # PeerJS protocol test, no root needed
```

## Submitting changes

1. Bump the version in `debian/changelog` (use `dch -i` for correct formatting).
2. Run `python3 -m py_compile wireguardrtc` and verify the man page renders
   without errors (`groff -t -man -Tascii wireguardrtc.8`).
3. Build and lint the package: `dpkg-buildpackage -us -uc -b && lintian ../wireguardrtc_*.deb`.
4. **Do not change `PROTOCOL_LABEL`** in the daemon source — it is part of
   the on-wire format. Changing it silently breaks interoperability with all
   deployed instances.
