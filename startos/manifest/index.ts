import { setupManifest } from '@start9labs/start-sdk'
import { bitcoinDescription, long, short } from './i18n'

export const manifest = setupManifest({
  id: 'sift',
  title: 'Sift',
  license: 'mit',
  packageRepo: 'https://github.com/Maveth/filter_sidecar',
  upstreamRepo: 'https://github.com/Maveth/filter_sidecar',
  marketingUrl: 'https://github.com/Maveth/filter_sidecar',
  donationUrl: null,
  description: { short, long },
  volumes: ['main'],
  images: {
    sift: {
      source: {
        dockerBuild: {
          dockerfile: 'Dockerfile',
          workdir: '.',
        },
      },
      arch: ['x86_64', 'aarch64'],
    },
  },
  dependencies: {
    bitcoind: {
      description: bitcoinDescription,
      optional: false,
      metadata: {
        title: 'Bitcoin',
        icon: 'https://raw.githubusercontent.com/Start9Labs/bitcoin-knots-startos/master/dep-icon.svg',
      },
    },
  },
})
