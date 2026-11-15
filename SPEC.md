# filter-sidecar design

Mining policy for one Knots node. The gateway never connects to this program. Knots builds the only template. This program decides which mempool transactions that template should leave out.

Not started against the live pool node. `dry_run` stays the default.

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

Phase 1 prints this difference in `dry_run`. It does not loosen the live node.

## Rules

`rules.json` is the policy. The program re-reads it every poll. Known checks and their numbers are a file change. A shape the checker has never heard of is still a code change in `spamcore.py`.

Local rules always win. A later downloaded list may add shapes. It cannot override a local "always mark" or "never mark". If the source is down, the last good local file stays. A bad file must not be able to mark ordinary payments. There is no download in the current program.

## Whitelist

A whitelist entry is a shape, plus an optional list of txids. It only saves a transaction Knots has already accepted. The sidecar leaves it unmarked so the node can mine it.

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

Not built. The page that exists today edits one rules file. The later screen has four tabs.

### Filter

The numbers and on/off rules in the list above. Each row shows the node value and the filter value. A row can be enabled or disabled. Enabling a row marks matching mempool transactions out of the template. It does not change what the node relays.

### Peers

A peers list in the shape of Bitcoin's peers window: direction, address, handshake result, whether that peer carries whitelist packages, spam shapes, or both, and how much has been exchanged.

Sidecars are not on the Bitcoin peer list and do not set a Bitcoin service bit. They listen on their own port. The default is the Bitcoin port plus 2. This node tells Bitcoin peers port 8333, so the default sidecar port is 8335. The port is a setting and can be changed. Inbound peers need that port open on the ISP port forward and on the firewall. A closed port still allows connections this sidecar starts.

Bootstrap tries each Bitcoin peer at that peer's Bitcoin port plus 2 and looks for the sidecar handshake. A peer that already gave a different sidecar port is dialed there. After the handshake, sidecars gossip their own addresses. The handshake says whether that operator offers whitelist packages, spam shapes, or both.

### Spam shapes

A list of custom shapes. The names and the schema for each one are in [shapes.json](shapes.json). That file is the catalog. It is not loaded by the running sidecar. Each row can be enabled or disabled for this filter. An enabled spam shape marks matching mempool transactions out of the template. A disabled shape is stored and is not applied. A shape received from a peer arrives disabled until the operator enables it.

### Whitelist

The first row is the Ark exit shape this program already knows: version 3, miner fee exactly 0, one zero-value pay-to-anchor, then the child that spends that anchor and pays the miner fee. The tab shows how to add another shape. It shows how many transactions of that shape are in the mempool now, and how many peers that packaged set was sent to.

Operators send and receive the packaged set. For a whitelist entry that set is the signed parent, then the child. Spam shapes travel the same way, as definitions rather than transactions. What arrives is kept like a small mempool of whitelist packages and spam shapes. Nothing in it applies until this operator enables it. An enabled whitelist package is inserted here (parent with `ignore_rejects`, then the child) and left unmarked so it can be mined. Enabling it does not make the Bitcoin node relay it to Bitcoin peers. Other sidecars receive it only on the sidecar port.

## New spam shapes

A known check or a number is data on the filter tab. A custom shape is a row on the spam-shapes tab. A shape the checker has never implemented is still a code change. The point of the app is that those definitions can change without a Knots rebuild, for transactions the node already accepts.

## Order of work

1. Catalog Knots filters against the sidecar rules and print the three sets. `dry_run` only.
2. Whitelist shapes and txids, including the local-insertion path.
3. Move the three tighter numbers onto the filter, and add the other mempool-membership options as filter rows that do nothing while the node is already tighter.
4. New spam patterns, then the custom spam-shape list.
5. The four tabs. The peers tab, the listen port, and the exchange of packages and shapes come after the local filter rows.
6. A signed feed of definitions. Local enable and disable still win.

## Not in this program

Consensus. A transaction the chain rejects cannot be marked in or out.

Sharing one mempool between two policies. The template filter remains the tool for a second cut.
