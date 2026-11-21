import { FileHelper, z } from '@start9labs/start-sdk'
import { sdk } from '../sdk'
import { nodePortDefault } from '../utils'

export const settingsShape = z.object({
  nodeHost: z.string().catch(''),
  nodePort: z.number().int().catch(nodePortDefault),
  dryRun: z.boolean().catch(false),
})

export type Settings = z.infer<typeof settingsShape>

export const settingsJson = FileHelper.json(
  {
    base: sdk.volumes.main,
    subpath: 'settings.json',
  },
  settingsShape,
)

export const runtimeConfig = FileHelper.json(
  {
    base: sdk.volumes.main,
    subpath: 'config.json',
  },
  z.object({
    rpc_url: z.string(),
    cookie_file: z.string(),
    rules_file: z.string(),
    shapes_file: z.string(),
    listen: z.string(),
    poll_seconds: z.number(),
    dry_run: z.boolean(),
  }),
)
