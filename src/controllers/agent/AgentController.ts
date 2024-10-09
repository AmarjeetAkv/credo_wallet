import type { RestAgentModules } from '../../cliAgent'
import type { AgentInfo } from '../types'

import { Agent } from '@credo-ts/core'
import { injectable } from 'tsyringe'

import ErrorHandlingService from '../../errorHandlingService'

import { Controller, Delete, Get, Route, Tags, Security } from 'tsoa'

@Tags('Agent')
@Route('/agent')
@injectable()
export class AgentController extends Controller {
  private agent: Agent<RestAgentModules>

  public constructor(agent: Agent<RestAgentModules>) {
    super()
    this.agent = agent
  }

  /**
   * Retrieve basic agent information
   */
  @Get('/')
  public async getAgentInfo(): Promise<AgentInfo> {
    try {
      return {
        label: this.agent.config.label,
        endpoints: this.agent.config.endpoints,
        isInitialized: this.agent.isInitialized,
        publicDid: undefined,
      }
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Delete wallet
   */
  @Security('apiKey')
  @Delete('/wallet')
  public async deleteWallet() {
    try {
      const deleteWallet = await this.agent.wallet.delete()
      return deleteWallet
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }
}
