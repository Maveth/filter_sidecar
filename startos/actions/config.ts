import { utils } from '@start9labs/start-sdk'
import { settingsJson } from '../fileModels/settings.json'
import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { nodePortDefault } from '../utils'

const { InputSpec, Value } = sdk

const inputSpec = InputSpec.of({
  nodeHost: Value.text({
    name: i18n('Node host'),
    required: false,
    default: '',
    placeholder: '',
    description: i18n('Blank uses Bitcoin on this server.'),
  }),
  nodePort: Value.number({
    name: i18n('Node port'),
    description: i18n(
      'Bitcoin RPC port. The StartOS package default is 8332, not a LAN port such as 65495.',
    ),
    required: true,
    default: nodePortDefault,
    min: 1,
    max: 65535,
    integer: true,
  }),
  dryRun: Value.toggle({
    name: i18n('Dry run'),
    default: false,
    description: i18n('On logs matches and does not mark the mempool.'),
  }),
})

export const connection = sdk.Action.withInput(
  'connection',
  async () => ({
    name: i18n('Connection'),
    description: i18n('Which Bitcoin node to read'),
    warning: null,
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  }),
  inputSpec,
  async ({ effects }) => settingsJson.read().const(effects),
  ({ effects, input }) =>
    settingsJson.merge(effects, utils.nullToUndefined(input) as object),
)
