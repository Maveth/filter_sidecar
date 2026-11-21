export const short = {
  en_US: 'Mark mempool transactions so Knots leaves them out of the block',
}

export const long = {
  en_US:
    'Reads the mempool of Bitcoin Knots on this server and marks the transactions the rules name. Knots then builds the block without them. The Sift page holds the rules. This package does not write bitcoin.conf and does not restart Knots. StartOS 0.4 only.',
}

export const bitcoinDescription = {
  en_US: 'The node whose mempool Sift reads. Sift uses that node’s RPC cookie.',
}
