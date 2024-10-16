import type { AgentMessageProcessedEvent, CredentialStateChangedEvent, InitConfig, ProofStateChangedEvent } from '@credo-ts/core'
import type { WalletConfig } from '@credo-ts/core/build/types'
import type { IndyVdrPoolConfig } from '@credo-ts/indy-vdr'

// import { PolygonDidRegistrar, PolygonDidResolver, PolygonModule } from '@ayanworks/credo-polygon-w3c-module'
import {
  AnonCredsCredentialFormatService,
  AnonCredsModule,
  AnonCredsProofFormatService,
  LegacyIndyCredentialFormatService,
  LegacyIndyProofFormatService,
  V1CredentialProtocol,
  V1ProofProtocol,
} from '@credo-ts/anoncreds'
import { AskarModule, AskarMultiWalletDatabaseScheme } from '@credo-ts/askar'
import {
  AutoAcceptCredential,
  AutoAcceptProof,
  DidsModule,
  ProofsModule,
  V2ProofProtocol,
  CredentialsModule,
  V2CredentialProtocol,
  ConnectionsModule,
  W3cCredentialsModule,
  KeyDidRegistrar,
  KeyDidResolver,
  CacheModule,
  InMemoryLruCache,
  WebDidResolver,
  HttpOutboundTransport,
  WsOutboundTransport,
  LogLevel,
  Agent,
  JsonLdCredentialFormatService,
  DifPresentationExchangeProofFormatService,
  MediationRecipientModule,
  MediatorPickupStrategy,
  ConnectionInvitationMessage,
  AgentEventTypes,
  CredentialEventTypes,
  ProofEventTypes,
  MediatorModule,
} from '@credo-ts/core'
import {
  IndyVdrAnonCredsRegistry,
  IndyVdrIndyDidResolver,
  IndyVdrModule,
  IndyVdrIndyDidRegistrar,
} from '@credo-ts/indy-vdr'
import { agentDependencies, HttpInboundTransport, WsInboundTransport } from '@credo-ts/node'
import { QuestionAnswerModule } from '@credo-ts/question-answer'
import { TenantsModule } from '@credo-ts/tenants'
import { anoncreds } from '@hyperledger/anoncreds-nodejs'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { indyVdr } from '@hyperledger/indy-vdr-nodejs'
import axios from 'axios'
import { randomBytes } from 'crypto'
import { readFile } from 'fs/promises'
import jwt from 'jsonwebtoken'

import { IndicioAcceptanceMechanism, IndicioTransactionAuthorAgreement, Network, NetworkName } from './enums/enum'
import { setupServer } from './server'
import { TsLogger } from './utils/logger'
import { Server, WebSocketServer } from 'ws'
import express from 'express'
import { Socket } from 'dgram'
import { connect } from 'ngrok'

export type Transports = 'ws' | 'http'
export type InboundTransport = {
  transport: Transports
  port: number
}

const inboundTransportMapping = {
  http: HttpInboundTransport,
  ws: WsInboundTransport,
} as const

const outboundTransportMapping = {
  http: HttpOutboundTransport,
  ws: WsOutboundTransport,
} as const

interface indyLedger {
  genesisTransactions: string
  indyNamespace: string
}
export interface AriesRestConfig {
  label: string
  walletConfig: WalletConfig
  indyLedger: indyLedger[]
  adminPort: number
  publicDidSeed?: string
  endpoints?: string[]
  autoAcceptConnections?: boolean
  autoAcceptCredentials?: AutoAcceptCredential
  autoAcceptProofs?: AutoAcceptProof
  logLevel?: LogLevel
  inboundTransports?: InboundTransport[]
  outboundTransports?: Transports[]
  autoAcceptMediationRequests?: boolean
  connectionImageUrl?: string
  tenancy?: boolean
  webhookUrl?: string
  didRegistryContractAddress?: string
  schemaManagerContractAddress?: string
  rpcUrl?: string
  fileServerUrl?: string
  fileServerToken?: string
  walletScheme?: AskarMultiWalletDatabaseScheme
  schemaFileServerURL?: string
}

export async function readRestConfig(path: string) {
  const configString = await readFile(path, { encoding: 'utf-8' })
  const config = JSON.parse(configString)

  return config
}

// export type RestMultiTenantAgentModules = Awaited<ReturnType<typeof getWithTenantModules>>

export type RestAgentModules = Awaited<ReturnType<typeof getModules>>

// TODO: add object
const getModules = (
  networkConfig: [IndyVdrPoolConfig, ...IndyVdrPoolConfig[]],
  didRegistryContractAddress: string,
  fileServerToken: string,
  fileServerUrl: string,
  rpcUrl: string,
  schemaManagerContractAddress: string,
  autoAcceptConnections: boolean,
  autoAcceptCredentials: AutoAcceptCredential,
  autoAcceptProofs: AutoAcceptProof,
  walletScheme: AskarMultiWalletDatabaseScheme
) => {
  const legacyIndyCredentialFormat = new LegacyIndyCredentialFormatService()
  const legacyIndyProofFormat = new LegacyIndyProofFormatService()
  const jsonLdCredentialFormatService = new JsonLdCredentialFormatService()
  const anonCredsCredentialFormatService = new AnonCredsCredentialFormatService()
  const anonCredsProofFormatService = new AnonCredsProofFormatService()
  const presentationExchangeProofFormatService = new DifPresentationExchangeProofFormatService()
  return {
    askar: new AskarModule({
      ariesAskar,
      multiWalletDatabaseScheme: walletScheme || AskarMultiWalletDatabaseScheme.ProfilePerWallet,
    }),

    indyVdr: new IndyVdrModule({
      indyVdr,
      networks: networkConfig,
    }),

    dids: new DidsModule({
      registrars: [new IndyVdrIndyDidRegistrar(), new KeyDidRegistrar()],
      resolvers: [new IndyVdrIndyDidResolver(), new KeyDidResolver(), new WebDidResolver()],
    }),

    anoncreds: new AnonCredsModule({
      registries: [new IndyVdrAnonCredsRegistry()],
      anoncreds,
    }),
    mediator: new MediatorModule({
      autoAcceptMediationRequests: true,
    }),
    mediationRecipient: new MediationRecipientModule({
      mediatorInvitationUrl: 'https://public.mediator.indiciotech.io?c_i=eyJAdHlwZSI6ICJkaWQ6c292OkJ6Q2JzTlloTXJqSGlxWkRUVUFTSGc7c3BlYy9jb25uZWN0aW9ucy8xLjAvaW52aXRhdGlvbiIsICJAaWQiOiAiMDVlYzM5NDItYTEyOS00YWE3LWEzZDQtYTJmNDgwYzNjZThhIiwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwczovL3B1YmxpYy5tZWRpYXRvci5pbmRpY2lvdGVjaC5pbyIsICJyZWNpcGllbnRLZXlzIjogWyJDc2dIQVpxSktuWlRmc3h0MmRIR3JjN3U2M3ljeFlEZ25RdEZMeFhpeDIzYiJdLCAibGFiZWwiOiAiSW5kaWNpbyBQdWJsaWMgTWVkaWF0b3IifQ==',
      mediatorPickupStrategy: MediatorPickupStrategy.Implicit,
    }),
    connections: new ConnectionsModule({
      autoAcceptConnections: autoAcceptConnections || true,
    }),
    proofs: new ProofsModule({
      autoAcceptProofs: autoAcceptProofs || AutoAcceptProof.ContentApproved,
      proofProtocols: [
        new V1ProofProtocol({
          indyProofFormat: legacyIndyProofFormat,
        }),
        new V2ProofProtocol({
          proofFormats: [legacyIndyProofFormat, anonCredsProofFormatService, presentationExchangeProofFormatService],
        }),
      ],
    }),
    credentials: new CredentialsModule({
      autoAcceptCredentials: autoAcceptCredentials || AutoAcceptCredential.Always,
      credentialProtocols: [
        new V1CredentialProtocol({
          indyCredentialFormat: legacyIndyCredentialFormat,
        }),
        new V2CredentialProtocol({
          credentialFormats: [
            legacyIndyCredentialFormat,
            jsonLdCredentialFormatService,
            anonCredsCredentialFormatService,
          ],
        }),
      ],
    }),
    w3cCredentials: new W3cCredentialsModule(),
    cache: new CacheModule({
      cache: new InMemoryLruCache({ limit: Number(process.env.INMEMORY_LRU_CACHE_LIMIT) || Infinity }),
    }),

    questionAnswer: new QuestionAnswerModule(),
    // polygon: new PolygonModule({
    //   didContractAddress: didRegistryContractAddress ? didRegistryContractAddress : (process.env.DID_CONTRACT_ADDRESS as string),
    //   schemaManagerContractAddress: schemaManagerContractAddress || (process.env.SCHEMA_MANAGER_CONTRACT_ADDRESS as string),
    //   fileServerToken: fileServerToken ? fileServerToken : (process.env.FILE_SERVER_TOKEN as string),
    //   rpcUrl: rpcUrl ? rpcUrl : (process.env.RPC_URL as string),
    //   serverUrl: fileServerUrl ? fileServerUrl : (process.env.SERVER_URL as string),
    // }),
  }
}

// TODO: add object
// const getWithTenantModules = (
//   networkConfig: [IndyVdrPoolConfig, ...IndyVdrPoolConfig[]],
//   didRegistryContractAddress: string,
//   fileServerToken: string,
//   fileServerUrl: string,
//   rpcUrl: string,
//   schemaManagerContractAddress: string,
//   autoAcceptConnections: boolean,
//   autoAcceptCredentials: AutoAcceptCredential,
//   autoAcceptProofs: AutoAcceptProof,
//   walletScheme: AskarMultiWalletDatabaseScheme
// ) => {
//   const modules = getModules(
//     networkConfig,
//     didRegistryContractAddress,
//     fileServerToken,
//     fileServerUrl,
//     rpcUrl,
//     schemaManagerContractAddress,
//     autoAcceptConnections,
//     autoAcceptCredentials,
//     autoAcceptProofs,
//     walletScheme
//   )
//   return {
//     tenants: new TenantsModule<typeof modules>({
//       sessionAcquireTimeout: Number(process.env.SESSION_ACQUIRE_TIMEOUT) || Infinity,
//       sessionLimit: Number(process.env.SESSION_LIMIT) || Infinity,
//     }),
//     ...modules,
//   }
// }

async function generateSecretKey(length: number = 32): Promise<string> {
  // Asynchronously generate a buffer containing random values
  const buffer: Buffer = await new Promise((resolve, reject) => {
    randomBytes(length, (error, buf) => {
      if (error) {
        reject(error)
      } else {
        resolve(buf)
      }
    })
  })

  // Convert the buffer to a hexadecimal string
  const secretKey: string = buffer.toString('hex')

  return secretKey
}

export async function runRestAgent(restConfig: AriesRestConfig) {
  const {
    schemaFileServerURL,
    logLevel,
    inboundTransports = [],
    outboundTransports = [],
    webhookUrl,
    adminPort,
    didRegistryContractAddress,
    fileServerToken,
    fileServerUrl,
    rpcUrl,
    schemaManagerContractAddress,
    walletConfig,
    autoAcceptConnections,
    autoAcceptCredentials,
    autoAcceptProofs,
    walletScheme,
    ...afjConfig
  } = restConfig

  const logger = new TsLogger(logLevel ?? LogLevel.error)

  const agentConfig:any = {
    walletConfig: {
      id: walletConfig.id,
      key: walletConfig.key,
      storage: walletConfig.storage,
    },
    // mediatorConnectionsInvite: 'https://http-mediator.nborbit.com?c_i=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL2Nvbm5lY3Rpb25zLzEuMC9pbnZpdGF0aW9uIiwgIkBpZCI6ICIzN2UwYjMxZC0yYWNiLTRjZDMtOTY1MS04NmMzOTFjZGNkZDAiLCAicmVjaXBpZW50S2V5cyI6IFsiOGVtajVaUFVZWkFEWldSdFJTN0xhWXFYOXl6eHdxR0ZGeWFGcHhBUUZ1dSJdLCAic2VydmljZUVuZHBvaW50IjogImh0dHBzOi8vaHR0cC1tZWRpYXRvci5uYm9yYml0LmNvbSIsICJsYWJlbCI6ICJNZWRpYXRvciJ9',
    // mediatorPickupStrategy: MediatorPickupStrategy.Implicit,
    // endpoints:['127.0.0.1:5000'],
    ...afjConfig,
    logger,
    autoUpdateStorageOnStartup: true,
    // As backup is only supported for sqlite storage
    // we need to manually take backup of the storage before updating the storage
    backupBeforeStorageUpdate: false,
  }

  async function fetchLedgerData(ledgerConfig: {
    genesisTransactions: string
    indyNamespace: string
  }): Promise<IndyVdrPoolConfig> {
    const urlPattern = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w-./?%&=]*)?$/

    if (!urlPattern.test(ledgerConfig.genesisTransactions)) {
      throw new Error('Not a valid URL')
    }

    const genesisTransactions = await axios.get(ledgerConfig.genesisTransactions)

    const networkConfig: IndyVdrPoolConfig = {
      genesisTransactions: genesisTransactions.data,
      indyNamespace: ledgerConfig.indyNamespace,
      isProduction: false,
      connectOnStartup: true,
    }

    if (ledgerConfig.indyNamespace.includes(NetworkName.Indicio)) {
      if (ledgerConfig.indyNamespace === (Network.Indicio_Mainnet as string)) {
        networkConfig.transactionAuthorAgreement = {
          version: IndicioTransactionAuthorAgreement.Indicio_Testnet_Mainnet_Version,
          acceptanceMechanism: IndicioAcceptanceMechanism.Wallet_Agreement,
        }
      } else {
        networkConfig.transactionAuthorAgreement = {
          version: IndicioTransactionAuthorAgreement.Indicio_Demonet_Version,
          acceptanceMechanism: IndicioAcceptanceMechanism.Wallet_Agreement,
        }
      }
    }

    return networkConfig
  }

  let networkConfig: [IndyVdrPoolConfig, ...IndyVdrPoolConfig[]]

  const parseIndyLedger = afjConfig?.indyLedger
  if (parseIndyLedger.length !== 0) {
    networkConfig = [
      await fetchLedgerData(parseIndyLedger[0]),
      ...(await Promise.all(parseIndyLedger.slice(1).map(fetchLedgerData))),
    ]
  } else {
    networkConfig = [
      {
        genesisTransactions: process.env.BCOVRIN_TEST_GENESIS as string,
        indyNamespace: Network.Bcovrin_Testnet,
        isProduction: false,
        connectOnStartup: true,
      },
    ]
  }

  // const tenantModule = await getWithTenantModules(
  //   networkConfig,
  //   didRegistryContractAddress || '',
  //   fileServerToken || '',
  //   fileServerUrl || '',
  //   rpcUrl || '',
  //   schemaManagerContractAddress || '',
  //   autoAcceptConnections || true,
  //   autoAcceptCredentials || AutoAcceptCredential.Always,
  //   autoAcceptProofs || AutoAcceptProof.ContentApproved,
  //   walletScheme || AskarMultiWalletDatabaseScheme.ProfilePerWallet
  // )
  const modules = getModules(
    networkConfig,
    didRegistryContractAddress || '',
    fileServerToken || '',
    fileServerUrl || '',
    rpcUrl || '',
    schemaManagerContractAddress || '',
    autoAcceptConnections || true,
    autoAcceptCredentials || AutoAcceptCredential.Always,
    autoAcceptProofs || AutoAcceptProof.ContentApproved,
    walletScheme || AskarMultiWalletDatabaseScheme.ProfilePerWallet
  )
  const agent = new Agent({
    config: agentConfig,
    modules: {
      ...modules,
    },
    dependencies: agentDependencies,
  })
  const config = agent.config

  const apps = express()
  // console.log('Apps:',apps);  
  const wsTransport = new WsOutboundTransport()
  const httpTransport = new HttpOutboundTransport()
  // const socketServer = new WebSocketServer({ port:4003,host:'127.0.0.1' })
  // console.log('socketServer:',socketServer)
  // const wsInboundTransport = new WsInboundTransport({server:socketServer})
  const httpInbound = new HttpInboundTransport({
    port:4002,
    app:apps,
    path:'/'
  })

  console.log('wsTransport: ',wsTransport)
  console.log('httpTransport: ',httpTransport)
  console.log('httpInbound: ',httpInbound)

  agent.registerOutboundTransport(wsTransport)
  agent.registerOutboundTransport(httpTransport)
  // agent.registerInboundTransport(wsInboundTransport)
  agent.registerInboundTransport(httpInbound);

  // httpInbound.app.get('/invitation', async (req, res) => {
  //   if (typeof req.query.d_m === 'string') {
  //     const invitation = await ConnectionInvitationMessage.fromUrl(req.url.replace('d_m=', 'c_i='))
  //     console.log('invitation:1',invitation)
  //     res.send(invitation.toJSON())
  //   }
  //   if (typeof req.query.c_i === 'string') {
  //     const invitation = await ConnectionInvitationMessage.fromUrl(req.url)
  //     console.log('invitation:2',invitation)
  //     res.send(invitation.toJSON())
  //   } else {
  //     const { outOfBandInvitation } = await agent.oob.createInvitation()
  //     // const endpoint = await connect(3001)
  //     const httpEndpoint = config.endpoints.find((e) => e.startsWith('http'))
  //     console.log('HttpsEndpoint',httpEndpoint)
  //     res.send(outOfBandInvitation.toUrl({ domain: httpEndpoint + '/invitation' }))
  //   }
  // })

  // const httpInbound = new HttpInboundTransport({
  //   port: 4002,
  // })

  // Register outbound transports
  console.log('outboundTransports: ',outboundTransports)
  console.log('inboundTransports: ',inboundTransports)
  // for (const outboundTransport of outboundTransports) {
  //   console.log('It outboundTransport',outboundTransport)
  //   const OutboundTransport = outboundTransportMapping[outboundTransport]
  //   agent.registerOutboundTransport(new OutboundTransport())
  // }

  // // Register inbound transports
  // for (const inboundTransport of inboundTransports) {
  //   console.log('It inboundTransports',inboundTransport)
  //   const InboundTransport = inboundTransportMapping[inboundTransport.transport]
  //   agent.registerInboundTransport(new InboundTransport({ port: inboundTransport.port }))
  // }

// console.log('httpInbound: ',httpInbound.start(agent))
//   // const endpoint = await connect(3001)
//   // console.log('Endpoint: ',endpoint)
//   httpInbound.app.get('/invitation', async (req, res) => {
//     console.log('Request: ',req)
//     console.log('Responses',res);
//     if (typeof req.query.c_i === 'string') {
//       const invitation = ConnectionInvitationMessage.fromUrl(req.url)
//       console.log('invitation httpInboundTransport :',invitation)
//       res.send(invitation.toJSON())
//     } else {
//       console.log('Else')
//       const { outOfBandInvitation } = await agent.oob.createInvitation()
//       const httpEndpoint = config.endpoints.find((e) => e.startsWith('http'))
//       console.log('HttpsEndpoint',httpEndpoint)
//       res.send(outOfBandInvitation.toUrl({ domain: httpEndpoint + '/invitation' }))
//     }
//   })
  console.log('Agent start init ')
  await agent.initialize()
  console.log('Agent start end ')

  agent.events.on(AgentEventTypes.AgentMessageProcessed, (data: AgentMessageProcessedEvent) => {
    agent.config.logger.debug(`Processed inbound message: ${JSON.stringify(data.payload.message.toJSON())}`)
  })

  agent.events.on(CredentialEventTypes.CredentialStateChanged,(data: CredentialStateChangedEvent)=>{
    console.log('🔥  * * * * * * CredentialStateChangedEvent emitted ::: ' + JSON.stringify(data));
    agent.config.logger.debug(`>> Credential state changed: ${JSON.stringify(data.payload.credentialRecord.toJSON())}`)
  })

  agent.events.on(ProofEventTypes.ProofStateChanged,(data: ProofStateChangedEvent)=>{
    console.log('🔥  * * * * * * Proof State Changed Event emitted ::: ' + JSON.stringify(data));
    agent.config.logger.debug(`>> Proof state changed: ${data}`)
  })
  let token: string = ''
  const genericRecord = await agent.genericRecords.getAll()

  const recordsWithToken = genericRecord.some((record) => record?.content?.token)
  if (!genericRecord.length || !recordsWithToken) {
    // Call the async function
    const secretKeyInfo: string = await generateSecretKey()
    // Check if the secretKey already exist in the genericRecords

    // if already exist - then don't generate the secret key again
    // Check if the JWT token already available in genericRecords - if yes, and also don't generate the JWT token
    // instead use the existin JWT token
    // if JWT token is not found, create/generate a new token and save in genericRecords
    // next time, the same token should be used - instead of creating a new token on every restart event of the agent

    // if already exist - then don't generate the secret key again
    // Check if the JWT token already available in genericRecords - if yes, and also don't generate the JWT token
    // instead use the existin JWT token
    // if JWT token is not found, create/generate a new token and save in genericRecords
    // next time, the same token should be used - instead of creating a new token on every restart event of the agent
    token = jwt.sign({ agentInfo: 'agentInfo' }, secretKeyInfo)
    await agent.genericRecords.save({
      content: {
        secretKey: secretKeyInfo,
        token,
      },
    })
  } else {
    const recordWithToken = genericRecord.find((record) => record?.content?.token !== undefined)

    token = recordWithToken?.content.token as string
  }
  const app = await setupServer(
    agent,
    {
      webhookUrl,
      port: adminPort,
      schemaFileServerURL,
    },
    token
  )

  logger.info(`*** API Token: ${token}`)

  app.listen(adminPort, () => {
    logger.info(`Successfully started server on port ${adminPort}`)
  })
}
