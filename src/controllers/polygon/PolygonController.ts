import type { RestAgentModules } from '../../cliAgent'
import type { SchemaMetadata } from '../types'

import { generateSecp256k1KeyPair } from '@ayanworks/credo-polygon-w3c-module'
import { DidOperation } from '@ayanworks/credo-polygon-w3c-module/build/ledger'
import { Agent } from '@credo-ts/core'
import * as fs from 'fs'
import { injectable } from 'tsyringe'

import ErrorHandlingService from '../../errorHandlingService'
import { BadRequestError, UnprocessableEntityError } from '../../errors'

import { Route, Tags, Security, Controller, Post, Body, Get, Path } from 'tsoa'

@Tags('Polygon')
@Security('apiKey')
@Route('/polygon')
@injectable()
export class Polygon extends Controller {
  private agent: Agent<RestAgentModules>

  public constructor(agent: Agent<RestAgentModules>) {
    super()
    this.agent = agent
  }

  /**
   * Create Secp256k1 key pair for polygon DID
   *
   * @returns Secp256k1KeyPair
   */
  @Post('create-keys')
  public async createKeyPair(): Promise<{
    privateKey: string
    publicKeyBase58: string
    address: string
  }> {
    try {
      return await generateSecp256k1KeyPair()
    } catch (error) {
      // Handle the error here
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Create polygon based W3C schema
   *
   * @returns Schema JSON
   */
  @Post('create-schema')
  public async createSchema(
    @Body()
    createSchemaRequest: {
      did: string
      schemaName: string
      schema: { [key: string]: any }
    }
  ): Promise<unknown> {
    try {
      const { did, schemaName, schema } = createSchemaRequest
      if (!did || !schemaName || !schema) {
        throw new BadRequestError('One or more parameters are empty or undefined.')
      }

      const schemaResponse = await this.agent.modules.polygon.createSchema({
        did,
        schemaName,
        schema,
      })
      if (schemaResponse.schemaState?.state === 'failed') {
        const reason = schemaResponse.schemaState?.reason?.toLowerCase()
        if (reason && reason.includes('insufficient') && reason.includes('funds')) {
          throw new UnprocessableEntityError(
            'Insufficient funds to the address, Please add funds to perform this operation'
          )
        } else {
          throw new Error(schemaResponse.schemaState?.reason)
        }
      }
      const schemaServerConfig = fs.readFileSync('config.json', 'utf-8')
      const configJson = JSON.parse(schemaServerConfig)
      if (!configJson.schemaFileServerURL) {
        throw new Error('Please provide valid schema file server URL')
      }

      if (!schemaResponse?.schemaId) {
        throw new BadRequestError('Invalid schema response')
      }
      const schemaPayload: SchemaMetadata = {
        schemaUrl: configJson.schemaFileServerURL + schemaResponse?.schemaId,
        did: schemaResponse?.did,
        schemaId: schemaResponse?.schemaId,
        schemaTxnHash: schemaResponse?.resourceTxnHash,
      }
      return schemaPayload
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Estimate transaction
   *
   * @returns Transaction Object
   */
  @Post('estimate-transaction')
  public async estimateTransaction(
    @Body()
    estimateTransactionRequest: {
      operation: any
      transaction: any
    }
  ): Promise<unknown> {
    try {
      const { operation } = estimateTransactionRequest

      if (!(operation in DidOperation)) {
        throw new BadRequestError('Invalid method parameter!')
      }
      if (operation === DidOperation.Create) {
        return this.agent.modules.polygon.estimateFeeForDidOperation({ operation })
      } else if (operation === DidOperation.Update) {
        return this.agent.modules.polygon.estimateFeeForDidOperation({ operation })
      }
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }

  /**
   * Fetch schema details
   *
   * @returns Schema Object
   */
  @Get(':did/:schemaId')
  public async getSchemaById(@Path('did') did: string, @Path('schemaId') schemaId: string): Promise<unknown> {
    try {
      return this.agent.modules.polygon.getSchemaById(did, schemaId)
    } catch (error) {
      throw ErrorHandlingService.handle(error)
    }
  }
}
