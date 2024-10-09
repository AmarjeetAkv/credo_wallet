import type { RestAgentModules } from '../../cliAgent'
import type { SchemaId } from '../examples'

import { getUnqualifiedCredentialDefinitionId, parseIndyCredentialDefinitionId } from '@credo-ts/anoncreds'
import { Agent } from '@credo-ts/core'
import { injectable } from 'tsyringe'

import { CredentialEnum, EndorserMode } from '../../enums/enum'
import ErrorHandlingService from '../../errorHandlingService'
import { ENDORSER_DID_NOT_PRESENT } from '../../errorMessages'
import { BadRequestError, InternalServerError, NotFoundError } from '../../errors/errors'
import { CredentialDefinitionExample, CredentialDefinitionId } from '../examples'

import { Body, Controller, Example, Get, Path, Post, Route, Tags, Security, Response } from 'tsoa'

@Tags('Credential Definitions')
@Route('/credential-definitions')
@Security('apiKey')
@injectable()
export class CredentialDefinitionController extends Controller {
  // TODO: Currently this only works if Extensible from credo-ts is renamed to something else, since there are two references to Extensible
  private agent: Agent<RestAgentModules>
  public constructor(agent: Agent<RestAgentModules>) {
    super()
    this.agent = agent
  }

  /**
   * Retrieve credential definition by credential definition id
   *
   * @param credentialDefinitionId
   * @returns CredDef
   */
  @Example(CredentialDefinitionExample)
  @Get('/:credentialDefinitionId')
  public async getCredentialDefinitionById(
    @Path('credentialDefinitionId') credentialDefinitionId: CredentialDefinitionId
  ) {
    try {
      const credentialDefinitionResult = await this.agent.modules.anoncreds.getCredentialDefinition(
        credentialDefinitionId
      )

      if (credentialDefinitionResult.resolutionMetadata?.error === 'notFound') {
        throw new NotFoundError(credentialDefinitionResult.resolutionMetadata.message)
      }
      const error = credentialDefinitionResult.resolutionMetadata?.error

      if (error === 'invalid' || error === 'unsupportedAnonCredsMethod') {
        throw new BadRequestError(credentialDefinitionResult.resolutionMetadata.message)
      }

      if (error !== undefined || credentialDefinitionResult.credentialDefinition === undefined) {
        throw new InternalServerError(credentialDefinitionResult.resolutionMetadata.message)
      }

      return credentialDefinitionResult
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Creates a new credential definition.
   *
   * @param credentialDefinitionRequest
   * @returns CredDef
   */
  @Example(CredentialDefinitionExample)
  @Response(200, 'Action required')
  @Response(202, 'Wait for action to complete')
  @Post('/')
  public async createCredentialDefinition(
    @Body()
    credentialDefinitionRequest: {
      issuerId: string
      schemaId: SchemaId
      tag: string
      endorse?: boolean
      endorserDid?: string
    }
  ) {
    try {
      const { issuerId, schemaId, tag, endorse, endorserDid } = credentialDefinitionRequest
      const credDef = {
        issuerId,
        schemaId,
        tag,
        type: 'CL',
      }
      const credentialDefinitionPayload = {
        credentialDefinition: credDef,
        options: {
          endorserMode: '',
          endorserDid: '',
          supportRevocation: false,
        },
      }
      if (!endorse) {
        credentialDefinitionPayload.options.endorserMode = EndorserMode.Internal
        credentialDefinitionPayload.options.endorserDid = issuerId
      } else {
        if (!endorserDid) {
          throw new BadRequestError(ENDORSER_DID_NOT_PRESENT)
        }
        credentialDefinitionPayload.options.endorserMode = EndorserMode.External
        credentialDefinitionPayload.options.endorserDid = endorserDid ? endorserDid : ''
      }

      const registerCredentialDefinitionResult = await this.agent.modules.anoncreds.registerCredentialDefinition(
        credentialDefinitionPayload
      )

      if (registerCredentialDefinitionResult.credentialDefinitionState.state === CredentialEnum.Failed) {
        throw new InternalServerError('Falied to register credef on ledger')
      }

      if (registerCredentialDefinitionResult.credentialDefinitionState.state === CredentialEnum.Wait) {
        // The request has been accepted for processing, but the processing has not been completed.
        this.setStatus(202)
        return registerCredentialDefinitionResult
      }

      if (registerCredentialDefinitionResult.credentialDefinitionState.state === CredentialEnum.Action) {
        return registerCredentialDefinitionResult
      }

      // TODO: Return uniform response for both Internally and Externally endorsed Schemas
      if (!endorse) {
        const indyCredDefId = parseIndyCredentialDefinitionId(
          registerCredentialDefinitionResult.credentialDefinitionState.credentialDefinitionId as string
        )
        const getCredentialDefinitionId = await getUnqualifiedCredentialDefinitionId(
          indyCredDefId.namespaceIdentifier,
          indyCredDefId.schemaSeqNo,
          indyCredDefId.tag
        )
        registerCredentialDefinitionResult.credentialDefinitionState.credentialDefinitionId = getCredentialDefinitionId
        return registerCredentialDefinitionResult.credentialDefinitionState
      }
      return registerCredentialDefinitionResult
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }
}
