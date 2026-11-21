# Sift

Marks transactions in the mempool of Bitcoin Knots on a StartOS 0.4 server, then leaves them out of the block. The existing Sift page is the screen for those rules. This package does not change Knots settings and it does not restart Knots.

Install Bitcoin Knots first, and leave it running. Then sideload this package and start it.

## Connection

Open **Sift**, then **Connection**.

- Leave **Node host** blank and **Node port** at **8332**. That uses Bitcoin on this same server.
- Leave **Dry run** off. On, Sift only logs and does not mark the mempool.

Saving restarts Sift so the new connection loads.

## Rules

Open the **Sift** interface. That is the same page used outside StartOS: each shape has a switch, and saving writes the rules file on this service. It does not write `bitcoin.conf`.

The switches start from the packaged example. Turn on only the rows you want.

## Peers

The hello port is for another Sift. The address on the **Interfaces** page is the one to publish. A loopback address cannot be dialed by anyone else.
