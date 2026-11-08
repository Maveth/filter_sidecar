# filter-sidecar

Mining policy for one Knots node. The gateway does not connect to it. The design and the limits are in [SPEC.md](SPEC.md).

This program watches one node's mempool. When a transaction matches the spam rules, it calls `prioritisetransaction` with a large negative fee adjustment and leaves that mark in place. The node builds the only template, and it does not pick the marked transaction. The block fills with everything else.

The mark does not stop relay. A transaction Knots has accepted is still announced. A transaction Knots rejects never reaches this program. Tightening what we mine is a rules change here. Loosening what Knots rejects is a Knots setting or a Knots build. A whitelist that needs a Knots setting lowered must say that this node will relay every transaction that setting newly accepts, and that only the whitelist is left unmarked so it can be mined.

One node can hold one policy. Every gateway that uses that node sees the same block. A second cut of the same mempool is what the template filter is for. Keep both.

## Do not start this on the live pool node

`dry_run` defaults to true. While it is true, the program only prints what it would mark. Set `dry_run` to false only on a node you mean to change. A node restart forgets the marks. This program walks the mempool again on its next poll.

The fee adjustment is larger than a block of fees, so a child cannot pay a marked parent back into a block. Children of a marked transaction are marked too.

## Rules file

`rules.json` is the policy. The names are the same ones the template filter uses. The program re-reads the file every poll. Drop in a new file and the next pass uses it. No version tag.

Turning a known check on or off, or changing a number such as `datacarriersize`, is a file change. A shape the checker has never heard of still needs a code change in `spamcore.py`. That file is the checker copied from the template filter so this app stands alone.

There is no download of rules. A bad file would mark real payments. Put the file here yourself.

## Run

```
cp config.json.example config.json
cp rules.json.example rules.json
python3 sidecar.py config.json
```

Set `rpc_url` and either `cookie_file` or `rpc_user` / `rpc_password`. Leave `dry_run` true until the log shows the transactions you expect.
