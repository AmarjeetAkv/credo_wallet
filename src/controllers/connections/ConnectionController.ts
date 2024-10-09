import type { RestAgentModules } from '../../cliAgent'
import type { ConnectionRecordProps } from '@credo-ts/core'

import { DidExchangeState, Agent } from '@credo-ts/core'
import { injectable } from 'tsyringe'

import ErrorHandlingService from '../../errorHandlingService'
import { NotFoundError } from '../../errors'
import { ConnectionRecordExample, RecordId } from '../examples'

import { Controller, Delete, Example, Get, Path, Post, Query, Route, Tags, Security } from 'tsoa'

@Tags('Connections')
@Route()
@injectable()
export class ConnectionController extends Controller {
  private agent: Agent<RestAgentModules>

  public constructor(agent: Agent<RestAgentModules>) {
    super()
    this.agent = agent
  }

  /**
   * Retrieve all connections records
   * @param alias Alias
   * @param state Connection state
   * @param myDid My DID
   * @param theirDid Their DID
   * @param theirLabel Their label
   * @returns ConnectionRecord[]
   */
  @Example<ConnectionRecordProps[]>([ConnectionRecordExample])
  @Security('apiKey')
  @Get('/connections')
  public async getAllConnections(
    @Query('outOfBandId') outOfBandId?: string,
    @Query('alias') alias?: string,
    @Query('state') state?: DidExchangeState,
    @Query('myDid') myDid?: string,
    @Query('theirDid') theirDid?: string,
    @Query('theirLabel') theirLabel?: string
  ) {
    try {
      const connections = await this.agent.connections.findAllByQuery({
        outOfBandId,
        alias,
        myDid,
        theirDid,
        theirLabel,
        state,
      })

      return connections.map((c) => c.toJSON())
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Retrieve connection record by connection id
   * @param connectionId Connection identifier
   * @returns ConnectionRecord
   */
  @Example<ConnectionRecordProps>(ConnectionRecordExample)
  @Security('apiKey')
  @Get('/connections/:connectionId')
  public async getConnectionById(@Path('connectionId') connectionId: RecordId) {
    try {
      const connection = await this.agent.connections.findById(connectionId)

      if (!connection) throw new NotFoundError(`Connection with connection id "${connectionId}" not found.`)

      return connection.toJSON()
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Deletes a connection record from the connection repository.
   *
   * @param connectionId Connection identifier
   */
  @Delete('/connections/:connectionId')
  @Security('apiKey')
  public async deleteConnection(@Path('connectionId') connectionId: RecordId) {
    try {
      this.setStatus(204)
      await this.agent.connections.deleteById(connectionId)
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Accept a connection request as inviter by sending a connection response message
   * for the connection with the specified connection id.
   *
   * This is not needed when auto accepting of connection is enabled.
   *
   * @param connectionId Connection identifier
   * @returns ConnectionRecord
   */
  @Example<ConnectionRecordProps>(ConnectionRecordExample)
  @Security('apiKey')
  @Post('/connections/:connectionId/accept-request')
  public async acceptRequest(@Path('connectionId') connectionId: RecordId) {
    try {
      const connection = await this.agent.connections.acceptRequest(connectionId)
      return connection.toJSON()
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Accept a connection response as invitee by sending a trust ping message
   * for the connection with the specified connection id.
   *
   * This is not needed when auto accepting of connection is enabled.
   *
   * @param connectionId Connection identifier
   * @returns ConnectionRecord
   */
  @Example<ConnectionRecordProps>(ConnectionRecordExample)
  @Security('apiKey')
  @Post('/connections/:connectionId/accept-response')
  public async acceptResponse(@Path('connectionId') connectionId: RecordId) {
    try {
      const connection = await this.agent.connections.acceptResponse(connectionId)
      return connection.toJSON()
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  @Get('/url/:invitationId')
  public async getInvitation(@Path('invitationId') invitationId: string) {
    try {
      const outOfBandRecord = await this.agent.oob.findByCreatedInvitationId(invitationId)

      if (!outOfBandRecord || outOfBandRecord.state !== 'await-response')
        throw new NotFoundError(`connection with invitationId "${invitationId}" not found.`)

      const invitationJson = outOfBandRecord.outOfBandInvitation.toJSON({ useDidSovPrefixWhereAllowed: true })
      return invitationJson
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }
}
