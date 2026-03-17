# nix-wire

Record, replay, and decode Nix daemon wire protocol sessions.

`nix-wire` interposes on the Nix daemon Unix socket to capture the full
bidirectional byte stream with nanosecond timestamps. Recordings can then be
decoded into human-readable operation traces or replayed against a daemon.

## Tools

**nix-wire-record** -- Proxy that sits between Nix clients and the daemon
socket, recording every session to a `.nixwire` file.

```
# Record local daemon (default store root /nix)
nix-wire-record

# Record with a custom store root
nix-wire-record --store /custom/nix

# Record wrapping a command (command mode)
nix-wire-record -- nix-daemon --stdio
```

**nix-wire-decode** -- Parses a recording and prints the protocol handshake,
each operation with timing/size, and a session summary.

```
nix-wire-decode --recording /nix/var/nix/nix-wire/0000.nixwire
```

Text output (default) shows one line per operation:

```
[     3.963ms] SetOptions                          req=   104B  stderr=1       0.029ms  STDERR_LAST  0 overrides
[     4.018ms] AddTempRoot                         req=    72B  stderr=1       0.086ms  STDERR_LAST  /nix/store/...
```

JSON output is also available with `--format json`.

Sync-detection guards emit `SYNC WARNING` messages to stderr when the decoder
encounters data that indicates stream corruption or misalignment (e.g. absurdly
large string lengths, non-zero padding bytes, out-of-range op codes). These
warnings are diagnostic -- the decoder continues best-effort.

**nix-wire-replay** -- Sends the client side of a recording to the daemon and
reads back responses.

```
# Replay against local daemon
nix-wire-replay --recording 0000.nixwire

# Replay against a command
nix-wire-replay --recording 0000.nixwire -- nix-daemon --stdio
nix-wire-replay --recording 0000.nixwire -- ssh host nix-daemon --stdio
```

## Recording ssh-ng:// sessions

To record wire protocol sessions on a remote machine accessed via `ssh-ng://`,
configure Nix to use `nix-wire-record` as the remote program wrapper:

```
nix build --store 'ssh-ng://user@host?remote-program=nix-wire-record -- nix-daemon' -f ...
```

This tells Nix to run `nix-wire-record -- nix-daemon --stdio` on the remote host
(Nix appends `--stdio` automatically). Recordings are written to
`/nix/var/nix/nix-wire/` on the remote machine by default.

To customize the output directory:

```
nix build --store 'ssh-ng://user@host?remote-program=nix-wire-record --output-dir /tmp/recordings -- nix-daemon'
```

You can then copy the recordings back and decode them locally:

```
scp 'user@host:/nix/var/nix/nix-wire/*.nixwire' ./recordings/
nix-wire-decode --recording ./recordings/0000.nixwire
```

Replaying against a remote daemon works the same way:

```
nix-wire-replay --recording 0000.nixwire -- ssh user@host nix-daemon --stdio
```

## NixOS module

A NixOS module is included to run the recorder as a systemd service alongside
`nix-daemon`:

```nix
{
  imports = [ nix-wire.nixosModules.default ];
  services.nix-wire-record.enable = true;
}
```

Recordings are written to `/nix/var/nix/nix-wire/` by default.

## Building

```
nix build
```

Or enter the dev shell and use cargo directly:

```
nix develop
cargo build
cargo test
```
