export const DEFAULT_LANG = 'en_US'

const dict = {
  'Sift is ready': 0,
  'The Sift page is not listening': 1,
  'Peer port is not listening': 2,
  Sift: 3,
  'Rules, marks, and peers': 4,
  Peers: 5,
  'Hello port for another Sift': 6,
  Connection: 7,
  'Which Bitcoin node to read': 8,
  'Node host': 9,
  'Blank uses Bitcoin on this server.': 10,
  'Node port': 11,
  'Bitcoin RPC port. The StartOS package default is 8332, not a LAN port such as 65495.': 12,
  'Page port': 13,
  'Port of the Sift page inside this service.': 14,
  'Peer port': 15,
  'Port another Sift dials.': 16,
  'Dry run': 17,
  'On logs matches and does not mark the mempool.': 18,
}

export type LangDict = typeof dict

export default dict
