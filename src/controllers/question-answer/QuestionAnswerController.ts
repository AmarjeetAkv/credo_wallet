import type { RestAgentModules } from '../../cliAgent'
import type { ValidResponse } from '@credo-ts/question-answer'

import { Agent } from '@credo-ts/core'
import { QuestionAnswerRecord, QuestionAnswerRole, QuestionAnswerState } from '@credo-ts/question-answer'
import { injectable } from 'tsyringe'

import ErrorHandlingService from '../../errorHandlingService'
import { NotFoundError } from '../../errors'
import { RecordId } from '../examples'

import { Body, Controller, Get, Path, Post, Route, Tags, Query, Security, Example } from 'tsoa'

@Tags('Question Answer')
@Route('/question-answer')
@Security('apiKey')
@injectable()
export class QuestionAnswerController extends Controller {
  private agent: Agent<RestAgentModules>

  public constructor(agent: Agent<RestAgentModules>) {
    super()
    this.agent = agent
  }

  /**
   * Retrieve question and answer records by query
   *
   * @param connectionId Connection identifier
   * @param role Role of the question
   * @param state State of the question
   * @param threadId Thread identifier
   * @returns QuestionAnswerRecord[]
   */
  @Get('/')
  public async getQuestionAnswerRecords(
    @Query('connectionId') connectionId?: string,
    @Query('role') role?: QuestionAnswerRole,
    @Query('state') state?: QuestionAnswerState,
    @Query('threadId') threadId?: string
  ) {
    try {
      const questionAnswerRecords = await this.agent.modules.questionAnswer.findAllByQuery({
        connectionId,
        role,
        state,
        threadId,
      })
      return questionAnswerRecords.map((record) => record.toJSON())
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Send a question to a connection
   *
   * @param connectionId Connection identifier
   * @param content The content of the message
   */
  @Example(QuestionAnswerRecord)
  @Post('question/:connectionId')
  public async sendQuestion(
    @Path('connectionId') connectionId: RecordId,
    @Body()
    config: {
      question: string
      validResponses: ValidResponse[]
      detail?: string
    }
  ) {
    try {
      const { question, validResponses, detail } = config

      const record = await this.agent.modules.questionAnswer.sendQuestion(connectionId, {
        question,
        validResponses,
        detail,
      })

      return record.toJSON()
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Send a answer to question
   *
   * @param id The id of the question answer record
   * @param response The response of the question
   */
  @Post('answer/:id')
  public async sendAnswer(@Path('id') id: RecordId, @Body() request: Record<'response', string>) {
    try {
      const record = await this.agent.modules.questionAnswer.sendAnswer(id, request.response)
      return record.toJSON()
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Retrieve question answer record by id
   * @param connectionId Connection identifier
   * @returns ConnectionRecord
   */
  @Get('/:id')
  public async getQuestionAnswerRecordById(@Path('id') id: RecordId) {
    try {
      const record = await this.agent.modules.questionAnswer.findById(id)

      if (!record) throw new NotFoundError(`Question Answer Record with id "${id}" not found.`)

      return record.toJSON()
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }
}
