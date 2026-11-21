import { FileHelper } from '@start9labs/start-sdk'
import { runtimeConfig, settingsJson, Settings } from './fileModels/settings.json'
import { i18n } from './i18n'
import { sdk } from './sdk'
import {
  bitcoindRpcUrl,
  dataDir,
  installDir,
  knotsMount,
  nodePortDefault,
  pagePortDefault,
  peerPortDefault,
} from './utils'

function upstreamFrom(settings: Settings, discovered: string | undefined): string {
  const host = (settings.nodeHost || '').trim()
  if (host) {
    const port = settings.nodePort || nodePortDefault
    return `http://${host}:${port}`
  }
  if (!discovered) {
    throw new Error('Bitcoin RPC address is not available yet')
  }
  return discovered
}

function mounts() {
  return sdk.Mounts.of()
    .mountVolume({
      volumeId: 'main',
      subpath: null,
      mountpoint: dataDir,
      readonly: false,
    })
    .mountDependency({
      dependencyId: 'bitcoind',
      volumeId: 'main',
      subpath: null,
      mountpoint: knotsMount,
      readonly: true,
    })
}

export const main = sdk.setupMain(async ({ effects }) => {
  const settings = (await settingsJson.read().const(effects)) ?? {
    nodeHost: '',
    nodePort: nodePortDefault,
    dryRun: false,
  }
  const discovered = await bitcoindRpcUrl(effects)
  const pagePort = pagePortDefault
  const peerPort = peerPortDefault
  await runtimeConfig.write(effects, {
    rpc_url: upstreamFrom(settings, discovered),
    cookie_file: `${knotsMount}/.cookie`,
    rules_file: `${dataDir}/rules.json`,
    shapes_file: `${installDir}/shapes.json`,
    listen: `0.0.0.0:${peerPort}`,
    poll_seconds: 10,
    dry_run: settings.dryRun === true,
  })

  const image = { imageId: 'sift' as const }
  const marker = await sdk.SubContainer.eager(effects, image, mounts(), 'sift-marker')
  const page = await sdk.SubContainer.eager(effects, image, mounts(), 'sift-page')
  const rootfs = await marker.rootfs
  await FileHelper.string(`${rootfs}${knotsMount}/.cookie`)
    .read(
      (cookie) => cookie,
      (prev, next) => next === null || prev === next,
    )
    .const(effects)

  return sdk.Daemons.of(effects)
    .addDaemon('marker', {
      subcontainer: marker,
      exec: { command: [`${installDir}/start-sidecar.sh`] },
      requires: [],
      ready: {
        display: i18n('Peers'),
        fn: () =>
          sdk.healthCheck.checkPortListening(effects, peerPort, {
            successMessage: i18n('Sift is ready'),
            errorMessage: i18n('Peer port is not listening'),
          }),
      },
    })
    .addDaemon('page', {
      subcontainer: page,
      exec: {
        command: [`${installDir}/start-page.sh`],
        env: { SIFT_PAGE_PORT: String(pagePort) },
      },
      requires: [],
      ready: {
        display: i18n('Sift'),
        fn: () =>
          sdk.healthCheck.checkPortListening(effects, pagePort, {
            successMessage: i18n('Sift is ready'),
            errorMessage: i18n('The Sift page is not listening'),
          }),
      },
    })
})
