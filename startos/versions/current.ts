import { VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '#sift:0.1.1:0',
  releaseNotes: {
    en_US:
      'One package for both Intel/AMD and ARM. Sift marks the Knots mempool from the rules on its own page. It does not change Knots settings.',
  },
  migrations: {
    up: async () => {},
    down: async () => {},
    other: {
      ['*']: {
        up: async () => {},
        down: async () => {},
      },
    },
  },
})
