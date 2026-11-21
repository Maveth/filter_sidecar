import { T } from '@start9labs/start-sdk'
import { sdk } from './sdk'

export const nodePortDefault = 8332
export const pagePortDefault = 8093
export const peerPortDefault = 8337
export const dataDir = '/data'
export const knotsMount = '/mnt/knots'
export const installDir = '/opt/sift'

export const btcRpcHostId = 'rpc'
export const uiHostId = 'ui'
export const peerHostId = 'peers'
export const uiInterfaceId = 'ui'
export const peerInterfaceId = 'peers'

export const bitcoindRpcUrl = async (effects: T.Effects) => {
  const bridge = await sdk.host
    .getBridgeAddress(effects, {
      packageId: 'bitcoind',
      hostId: btcRpcHostId,
      internalPort: nodePortDefault,
      ssl: false,
    })
    .const()
  return bridge == null ? undefined : `http://${bridge}`
}
