import type { BaseError } from '../errors/errors'

import { errorMap } from '../errors/errors'

function convertError(errorType: string, message: string = 'An error occurred'): BaseError {
  const ErrorClass = errorMap[errorType] || errorMap.InternalServerError
  throw new ErrorClass(message)
}

export default convertError
