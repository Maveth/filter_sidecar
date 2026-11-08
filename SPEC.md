# filter-sidecar design

Mining policy for one Knots node. The gateway never connects to this program. Knots builds the only template. This program decides which mempool transactions that template should leave out.

Not started against the live pool node. `dry_run` stays the default.

## What it does

The sidecar watches one node's mempool. A transaction that matches the spam rules gets `prioritisetransaction` with a negative fee larger than a whole block of fees. The mark stays. Children of a marked transaction are marked too. Knots then builds the block and does not pick the marked transactions.

A node restart forgets the marks. The next poll walks the mempool and marks again.

One node holds one policy. Every gateway that uses that node sees the same block. A second cut of the same mempool is the template filter, not a second sidecar on this node. Two policies means two Knots nodes, each with its own sidecar.

## What it does not do

It does not decide what enters the mempool. Knots does. A transaction Knots rejects never reaches the sidecar, so a sidecar rule for that shape does nothing.

It does not stop relay. Knots policy flags are relay and mine together. Once a transaction is in the mempool, this node announces it. There is no RPC to keep a transaction and not relay it. A fee mark only changes mining.

It does not change Knots settings. Loosening a Knots reject still needs a Knots startup setting or a Knots build. Tightening, for transactions Knots has already accepted, is a rules change here.

## Three sets

Every rule the app knows belongs in one of these:

| Set | Meaning |
| --- | --- |
| Knots already enforces | The node rejects it. The sidecar never sees it. Turning the sidecar check on changes nothing until Knots is loosened. |
| Sidecar only | Knots accepts it. The sidecar mark keeps it out of the block. It is still relayed. |
| Knots blocks first | A whitelist or a new pattern wants it mined, but Knots rejects it today. The app must say which Knots setting or build would let it in. |

Phase 1 prints this difference in `dry_run`. It does not loosen the live node.

## Rules

`rules.json` is the policy. The program re-reads it every poll. Known checks and their numbers are a file change. A shape the checker has never heard of is still a code change in `spamcore.py`.

Local rules always win. A later downloaded list may add shapes. It cannot override a local "always mark" or "never mark". If the source is down, the last good local file stays. A bad file must not be able to mark ordinary payments. There is no download in the current program.

## Whitelist

A whitelist entry is a shape, plus an optional list of txids. It only saves a transaction Knots has already accepted. The sidecar leaves it unmarked so the node can mine it.

A whitelist entry Knots currently rejects must say so before it is enabled. Letting it in means lowering a Knots relay-and-mine setting. After that, this node relays every transaction the lowered rule accepts, including ones that are not on the whitelist. The sidecar can keep those extra ones out of the block. It cannot keep them out of the mempool, and it cannot stop the relay. The whitelisted transaction is relayed too.

Connor's Ark package is the first whitelist of this kind. It is a v3 transaction with one parent and one child, and a zero-fee parent whose one dust anchor is spent by the paying child in the same package. The match has to be that format, not merely "it has a dust anchor", because anyone can build the loose shape. This Knots already has `-mempooltruc=enforce` as a startup flag (default is `accept`). The exact zero-fee dust-parent check is not a setting. It is Knots code this binary does not have. A fee boost fights that check. Turning `-subdustfeepenalty` off is wider than the whitelist and is the case the warning above is for.

## New spam shapes

A new magic, size, or known check is data in `rules.json`. A shape the checker has never implemented is a code change. The point of the app is that those definitions can change without a Knots rebuild, for transactions the node already accepts.

## Order of work

1. Catalog Knots filters against the sidecar rules and print the three sets. `dry_run` only.
2. Whitelist shapes and txids, including the Knots-setting warning.
3. New spam patterns in the checker.
4. A signed feed of definitions. Local rules still win.
5. A UI for the rules and the diff. The UI edits sidecar policy only.

## Not in this program

Consensus. A transaction the chain rejects cannot be marked in or out.

Sharing one mempool between two policies. The template filter remains the tool for a second cut.
