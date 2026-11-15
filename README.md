# Sift

A spam filter and whitelist sidecar for a Bitcoin node. The repository name stays `filter_sidecar`. The limits that do not change are in [SPEC.md](SPEC.md).

Sift watches one node's mempool. A transaction that matches a spam check gets `prioritisetransaction` with a negative fee larger than a block of fees, so the node leaves it out of the block. Children of a marked transaction are marked too. The mark does not stop relay. Knots builds the only template. The gateway does not connect to this program.

One node holds one policy. A second cut of the same mempool is the template filter, not a second sidecar on this node.

## What a startup reads

A startup reads local files. It does not call GitHub.

`rules.json` is the on/off switch and the numbers. The marker re-reads it every poll. This file is not downloaded. A remote copy of it could mark ordinary payments.

`shapes.json` is the catalog. Spam rows are `SFS-1` and up, whitelist rows are `WLS-1` and up, and watch rows are `WCH-1` and up. The number is the id. The old name is the slug. `shapes/` holds the same catalog as one file per shape, which is what the download button fetches.

A shape is JSON. Its `checker` field names a function already compiled into `spamcore.py`. The numbers live in the rules file. A checker name this copy does not have is stored and does not run. A new way to look at a transaction is still a change to `spamcore.py`, then a shape file that names it.

A fresh copy of this repo already contains the catalog, so the first start does not need the network.

## Download

The gear on the page has Download shapes. It fetches ids that are missing from `https://raw.githubusercontent.com/Maveth/filter_sidecar/main/shapes` and appends them. It does not replace `rules.json`. A new shape stays off until it is turned on, and it still does nothing unless this copy has that checker.

## Run

```
cp config.json.example config.json
cp rules.json.example rules.json
python3 sidecar.py config.json
```

Put the node login only in `config.json`. That file is not committed. `config.json.example` leaves the user and the password empty and points at `127.0.0.1`. Use a cookie file or fill in the user and password locally. Leave `dry_run` true until the log shows the transactions you expect. A node restart forgets the marks. The next poll walks the mempool again.

Do not start this against the live pool node until `dry_run` has shown the marks you expect.

## Page

```
python3 ui.py rules.json
```

Opens `http://127.0.0.1:8093/`. The arguments after the rules file are the port, the log file, and an optional bind address. The page lists the catalog, the peers, and the gear for settings, the log, and the inbox. It does not write `bitcoin.conf` and it does not restart the node.

To show this node's policy lines, add `node-paths.json` next to the program. The key is the log file name and the value is the conf path. Only the policy lines in that file are read. An RPC line in the conf is not shown.

## Peers

A sidecar listens on its own port. The usual search looks at each Bitcoin peer on that peer's port plus 2. The hello carries the catalog and the git commit of this checkout. Shape definitions are offered. A signed whitelist package is dropped unless the operator turns on accept packages. A received shape stays off. A sidecar does not learn other sidecars from a sidecar.

## Not in this repository

No RPC password, no cookie, no peer address, and no path on this machine. `config.json`, the peer files, the inbox, and `node-paths.json` stay on the machine that runs Sift.
