import type { RestAgentModules } from '../../cliAgent'
import type { BasicMessageRecord, BasicMessageStorageProps } from '@credo-ts/core'

import { Agent } from '@credo-ts/core'
import { injectable } from 'tsyringe'

import ErrorHandlingService from '../../errorHandlingService'
import { BasicMessageRecordExample, RecordId } from '../examples'

import { Body, Controller, Example, Get, Path, Post, Route, Tags, Security } from 'tsoa'

@Tags('Basic Messages')
@Route('/basic-messages')
@Security('apiKey')
@injectable()
export class BasicMessageController extends Controller {
  private agent: Agent<RestAgentModules>

  public constructor(agent: Agent<RestAgentModules>) {
    super()
    this.agent = agent
  }

  /**
   * Retrieve basic messages by connection id
   *
   * @param connectionId Connection identifier
   * @returns BasicMessageRecord[]
   */
  @Example<BasicMessageStorageProps[]>([BasicMessageRecordExample])
  @Get('/:connectionId')
  public async getBasicMessages(@Path('connectionId') connectionId: RecordId): Promise<BasicMessageRecord[]> {
    try {
      const basicMessageRecords = await this.agent.basicMessages.findAllByQuery({ connectionId })
      this.setStatus(200)
      return basicMessageRecords
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Send a basic message to a connection
   *
   * @param connectionId Connection identifier
   * @param content The content of the message
   */
  @Example<BasicMessageStorageProps>(BasicMessageRecordExample)
  @Post('/:connectionId')
  public async sendMessage(@Path('connectionId') connectionId: RecordId, @Body() request: Record<'content', string>) {
    try {
      const basicMessageRecord = await this.agent.basicMessages.sendMessage(connectionId, request.content)
      this.setStatus(204)
      return basicMessageRecord
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }
}
