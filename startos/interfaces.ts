import { i18n } from './i18n'
import { sdk } from './sdk'
import {
  pagePortDefault,
  peerHostId,
  peerInterfaceId,
  peerPortDefault,
  uiHostId,
  uiInterfaceId,
} from './utils'

export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const uiOrigin = await sdk.MultiHost.of(effects, uiHostId).bindPort(pagePortDefault, {
    protocol: 'http',
  })
  const ui = sdk.createInterface(effects, {
    name: i18n('Sift'),
    id: uiInterfaceId,
    description: i18n('Rules, marks, and peers'),
    type: 'ui',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })
  const peerOrigin = await sdk.MultiHost.of(effects, peerHostId).bindPort(peerPortDefault, {
    protocol: null,
    addSsl: null,
    preferredExternalPort: peerPortDefault,
    secure: { ssl: false },
  })
  const peers = sdk.createInterface(effects, {
    name: i18n('Peers'),
    id: peerInterfaceId,
    description: i18n('Hello port for another Sift'),
    type: 'p2p',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })
  return [await uiOrigin.export([ui]), await peerOrigin.export([peers])]
})
