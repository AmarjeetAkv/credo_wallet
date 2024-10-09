import type { Version } from '../examples'
import type { IndyVdrDidCreateOptions } from '@credo-ts/indy-vdr'

import {
  getUnqualifiedCredentialDefinitionId,
  getUnqualifiedSchemaId,
  parseIndyCredentialDefinitionId,
  parseIndySchemaId,
} from '@credo-ts/anoncreds'
import { Agent } from '@credo-ts/core'
import { injectable } from 'tsyringe'

import { CredentialEnum, EndorserMode } from '../../enums/enum'
import ErrorHandlingService from '../../errorHandlingService'
import { BadRequestError } from '../../errors'
import { DidNymTransaction, EndorserTransaction, WriteTransaction } from '../types'

import { Body, Controller, Post, Route, Tags, Security } from 'tsoa'

@Tags('EndorserTransaction')
@Route('/transactions')
@Security('apiKey')
@injectable()
export class EndorserTransactionController extends Controller {
  private agent: Agent

  public constructor(agent: Agent) {
    super()
    this.agent = agent
  }

  @Post('/endorse')
  public async endorserTransaction(@Body() endorserTransaction: EndorserTransaction) {
    try {
      if (!endorserTransaction.transaction) {
        throw new BadRequestError('Transaction is required')
      }
      if (!endorserTransaction.endorserDid) {
        throw new BadRequestError('EndorserDid is required')
      }
      const signedTransaction = await this.agent.modules.indyVdr.endorseTransaction(
        endorserTransaction.transaction,
        endorserTransaction.endorserDid
      )

      return { signedTransaction }
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  @Post('/set-endorser-role')
  public async didNymTransaction(@Body() didNymTransaction: DidNymTransaction) {
    try {
      const didCreateSubmitResult = await this.agent.dids.create<IndyVdrDidCreateOptions>({
        did: didNymTransaction.did,
        options: {
          endorserMode: EndorserMode.External,
          endorsedTransaction: {
            nymRequest: didNymTransaction.nymRequest,
          },
        },
      })

      return didCreateSubmitResult
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  @Post('/write')
  public async writeSchemaAndCredDefOnLedger(
    @Body()
    writeTransaction: WriteTransaction
  ) {
    try {
      if (writeTransaction.schema) {
        const writeSchema = await this.submitSchemaOnLedger(
          writeTransaction.schema,
          writeTransaction.endorsedTransaction
        )
        return writeSchema
      } else if (writeTransaction.credentialDefinition) {
        const writeCredDef = await this.submitCredDefOnLedger(
          writeTransaction.credentialDefinition,
          writeTransaction.endorsedTransaction
        )
        return writeCredDef
      } else {
        throw new Error('Please provide valid schema or credential-def!')
      }
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  public async submitSchemaOnLedger(
    schema: {
      issuerId: string
      name: string
      version: Version
      attributes: string[]
    },
    endorsedTransaction?: string
  ) {
    if (!schema.issuerId) {
      throw new BadRequestError('IssuerId is required')
    }
    if (!schema.name) {
      throw new BadRequestError('Name is required')
    }
    if (!schema.version) {
      throw new BadRequestError('Version is required')
    }
    if (!schema.attributes) {
      throw new BadRequestError('Attributes is required')
    }
    const { issuerId, name, version, attributes } = schema
    const { schemaState } = await this.agent.modules.anoncreds.registerSchema({
      options: {
        endorserMode: EndorserMode.External,
        endorsedTransaction,
      },
      schema: {
        attrNames: attributes,
        issuerId: issuerId,
        name: name,
        version: version,
      },
    })

    const indySchemaId = parseIndySchemaId(schemaState.schemaId)
    const getSchemaUnqualifiedId = await getUnqualifiedSchemaId(
      indySchemaId.namespaceIdentifier,
      indySchemaId.schemaName,
      indySchemaId.schemaVersion
    )
    if (schemaState.state === CredentialEnum.Finished || schemaState.state === CredentialEnum.Action) {
      schemaState.schemaId = getSchemaUnqualifiedId
    }
    return schemaState
  }

  public async submitCredDefOnLedger(
    credentialDefinition: {
      schemaId: string
      issuerId: string
      tag: string
      value: unknown
      type: string
    },
    endorsedTransaction?: string
  ) {
    if (!credentialDefinition.schemaId) {
      throw new BadRequestError('SchemaId is required')
    }
    if (!credentialDefinition.issuerId) {
      throw new BadRequestError('IssuerId is required')
    }
    if (!credentialDefinition.tag) {
      throw new BadRequestError('Tag is required')
    }
    if (!credentialDefinition.value) {
      throw new BadRequestError('Value is required')
    }
    if (!credentialDefinition.type) {
      throw new BadRequestError('Type is required')
    }
    const { credentialDefinitionState } = await this.agent.modules.anoncreds.registerCredentialDefinition({
      credentialDefinition,
      options: {
        endorserMode: EndorserMode.External,
        endorsedTransaction: endorsedTransaction,
      },
    })

    const indyCredDefId = parseIndyCredentialDefinitionId(credentialDefinitionState.credentialDefinitionId)
    const getCredentialDefinitionId = await getUnqualifiedCredentialDefinitionId(
      indyCredDefId.namespaceIdentifier,
      indyCredDefId.schemaSeqNo,
      indyCredDefId.tag
    )
    if (
      credentialDefinitionState.state === CredentialEnum.Finished ||
      credentialDefinitionState.state === CredentialEnum.Action
    ) {
      credentialDefinitionState.credentialDefinitionId = getCredentialDefinitionId
    }
    return credentialDefinitionState
  }
}
