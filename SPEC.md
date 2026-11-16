# filter-sidecar design

Mining policy for one Knots node. The gateway never connects to this program. Knots builds the only template. This program decides which mempool transactions that template should leave out.

`dry_run` is off unless the config sets it true. A missing key starts live.

## What it does

The sidecar watches one node's mempool. A transaction that matches the spam rules gets `prioritisetransaction` with a negative fee larger than a whole block of fees. The mark stays. Children of a marked transaction are marked too. Knots then builds the block and does not pick the marked transactions.

A node restart forgets the marks. The next poll walks the mempool and marks again.

One node holds one policy. Every gateway that uses that node sees the same block. A second cut of the same mempool is the template filter, not a second sidecar on this node. Two policies means two Knots nodes, each with its own sidecar.

## What it does not do

It does not decide what enters the mempool. Knots does. A transaction Knots rejects never reaches the sidecar, so a sidecar rule for that shape does nothing until the node lets it in.

It does not stop relay. Not now, and not in a later version. Knots policy flags are relay and mine together. Once a transaction is in the mempool, this node announces it. There is no RPC to keep a transaction and not relay it. A fee mark, a tighter filter number, a custom spam shape, or a disabled whitelist only changes what this node mines. Bitcoin peers still receive what Knots accepted.

It does not change Knots settings. The screens below write the sidecar's own files. They do not write `bitcoin.conf` and they do not restart Knots.

## Three sets

Every rule the app knows belongs in one of these:

| Set | Meaning |
| --- | --- |
| Knots already enforces | The node rejects it on the public peer port. A sidecar rule does not loosen the node. A whitelisted shape that Knots rejects is inserted by this sidecar with `sendrawtransaction` and `ignore_rejects`, not by a wider startup policy. |
| Sidecar only | Knots accepts it. The sidecar mark keeps it out of the block. It is still relayed. |
| Knots blocks first | A whitelist or a new pattern wants it mined, but Knots rejects it today. The app must say which Knots setting or build would let it in. |

With `dry_run` set true, the log prints this difference and the node is not changed. It does not loosen the live node.

## Rules

`rules.json` is the policy. The program re-reads it every poll. Known checks and their numbers are a file change. A shape names a checker compiled into `spamcore.py`. A checker this copy does not have does not run. A new way to inspect a transaction is still a code change.

Local rules always win. The catalog is `shapes.json`, and the marker loads that file at startup. It does not call GitHub. The page can download shape ids that the local catalog does not have yet. A downloaded shape is stored and stays off. The download does not replace `rules.json`. If the source is down, the local file stays. A bad rules file must not be fetched, because it could mark ordinary payments.

## Whitelist

A whitelist entry is a shape, plus an optional list of txids. It only saves a transaction Knots has already accepted. The sidecar leaves it unmarked and adds 1000 sats of mining priority to that transaction and its descendants. Knots refuses priority on a dust output, so a zero-value anchor parent gets that 1000 on its descendants instead. The priority stays on this node. It is not relayed.

A whitelist entry Knots currently rejects stays rejected on the public peer port. Letting that one shape in does not mean lowering a Knots relay-and-mine setting. The sidecar inserts the signed transaction with `sendrawtransaction` and `ignore_rejects`. The node stays strict, so it does not start relaying every transaction a wider policy would accept.

Connor's Ark package is the first whitelist of this kind. It is a version-3 parent with miner fee exactly 0 and one zero-value pay-to-anchor, then a child that spends the anchor and pays the miner fee. The match has to be that format, not merely "it has a dust anchor". The parent is sent first with the fee and dust reasons ignored. The child is a normal `sendrawtransaction` after the parent is in the mempool. `submitpackage` is not used until that RPC keeps `ignore_rejects` through `SingleInPackageAccept`.

## The node we assume, and three tighter numbers

For now the node stays on ordinary Knots policy. Three numbers in the live config are tighter than a normal Knots install. They are mining choices, not something the node has to enforce:

| Number | Normal Knots | Live config | On the filter |
| --- | --- | --- | --- |
| Additional data size (`datacarriersize`) | 83 bytes | 42 | 42 or smaller |
| Data weight (`datacarriercost`) | 1 virtual byte per real byte | 2 | 2 or higher |
| Minimum bytes per sigop (`bytespersigopstrict`) | 20 | 51 | 51 or higher |

Those three can live on the filter instead of in Knots. Making them tighter still is a filter change. Putting the node back to the normal numbers would let the larger data, the cheaper data bytes, and the denser sigops into the mempool, and this node would relay them. The filter would then be what keeps them out of the block.

The same idea covers the other Knots controls that decide mempool membership, for a later day when Knots is looser than this miner wants. Each one becomes a filter option only because it changes what can sit in the mempool. The filter still cannot stop relay. If the node is already tighter, the filter line does nothing until the node lets the transaction in.

Mempool membership, from the Knots spam and mempool screens: unrecognised scripts, unknown witness versions, parasites, tokens, minimum fee, coin-age delay, maturity delay, both sigop numbers, ancestor count and size, descendant count and size, bare pubkey, bare multisig, the ephemeral-output choice, anchor-only transactions, script size, legacy sigops, data size, non-standard data formats, dust, data-only transactions, dynamic dust, address reuse, and TRUC. The sub-dust fee penalty, the data-byte weight, and the ordinary sigop weight do not remove a transaction by themselves. They still belong on the filter tab, because they change what is mined.

Block size, coin-age priority space, and maximum block weight are not filter options. They cap the block. Mempool capacity, expiry, replacement, and the unconnected-transaction cap are not filter options either. They do not name a shape to leave out.

## Screens

The page lists spam and whitelist as rows, keeps those rows at the top, and opens settings from the gear. The gear holds the peer search, accepting signed packages, importing a private shape, downloading missing shapes, the node's policy lines, a sample `bitcoin.conf`, the log, and the inbox. `/settings` is the long rules form. The page does not write `bitcoin.conf`.

### Filter

The numbers and on/off rules in the list above. Each row shows the node value and the filter value. A row can be enabled or disabled. Enabling a row marks matching mempool transactions out of the template. It does not change what the node relays.

### Peers

The peers table shows direction, handshake, catalog, the other sidecar's commit, and what it carries. An operator can add an address, search Bitcoin peers at their port plus 4, and delete an address they added. The added number is a setting and starts at 4. Each Bitcoin peer is checked once an hour. A sidecar sends the announced addresses it knows, and passes on a new one when that sidecar connects.

Sidecars are not on the Bitcoin peer list and do not set a Bitcoin service bit. They listen on their own port. The search uses the Bitcoin port plus 4 unless the operator picks another offset. Inbound peers need that port open. A closed port still allows connections this sidecar starts.

### Spam shapes

The catalog is [shapes.json](shapes.json). The running sidecar loads it. Each row can be turned on or off in the rules file. An enabled spam shape marks matching mempool transactions out of the template when this copy has that checker. A disabled shape is stored and is not applied. A shape received from a peer arrives disabled. Turning it on does not by itself make this copy mark it.

### Whitelist

WLS-1 is the Ark exit this program already knows: version 3, miner fee exactly 0, one zero-value pay-to-anchor, then the child that spends that anchor and pays the miner fee. Test on a row counts what that one check would put back in the current mempool, and what would stay marked by another check.

Shape definitions are what peers exchange. A signed parent and child are kept only when the operator accepts packages. A received shape stays off. Enabling a received shape does not by itself mark or insert anything. The Ark parent is inserted by this sidecar with `ignore_rejects` when that whitelist is on. That does not make the node relay it to Bitcoin peers.

## New spam shapes

A known check or a number is data in the rules file. A custom shape is a catalog row that names a checker this copy already has. A shape the checker has never implemented is still a code change. The definitions can change without a Knots rebuild, for transactions the node already accepts. They cannot add a new checker by themselves.

## Where the work stands

The catalog, the rules file, the page, and the port-plus-4 search are in the program. A hello lists shape ids and package hashes. A peer asks for the ones it lacks. The package hash is sha256 of the shape id and the transactions in that one set. WLS-1 is one Ark parent and its child. WLS-2 is one low-fee transaction plus the descendants that pay for it. A separate pair is a separate hash. A mismatch is dropped. Signed packages are fetched only when the operator accepts packages. A verified package is then inserted one transaction after another. WLS-1 already defines that bypass: the parent uses sendrawtransaction with ignore_rejects, then the child is a normal sendrawtransaction. A conflict is not retried, and submitpackage is not used. The three tighter numbers above are still the live node's numbers: data size 42, data weight 2, and 51 bytes per sigop.

Not built: sidecars learning sidecars from other sidecars, a received shape applying just because it was enabled, and a signed feed that replaces the local rules. Local enable and disable still win.

## Not in this program

Consensus. A transaction the chain rejects cannot be marked in or out.

Sharing one mempool between two policies. The template filter remains the tool for a second cut.
