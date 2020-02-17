
import * as FA from '../'

import frontAuth from '../src/frontAuth'
import getAuthorizedRequest from '../src/getAuthorizedRequest'
import setCookieResponse from '../src/setCookieResponse'


describe('frontAuth', () => {

  test('has frontAuth', () => {
    expect(frontAuth).toBeDefined()
    expect(FA.frontAuth).toBe(frontAuth)
  })

  test('has getAuthorizedRequest', () => {
    expect(getAuthorizedRequest).toBeDefined()
    expect(FA.getAuthorizedRequest).toBe(getAuthorizedRequest)
  })

  test('has setCookieResponse', () => {
    expect(setCookieResponse).toBeDefined()
    expect(FA.setCookieResponse).toBe(setCookieResponse)
  })

})

