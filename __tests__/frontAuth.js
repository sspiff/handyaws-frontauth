
import {
  createKeyPair,
  jwtSign,
  publicKeyFromKeyPair,
  KeyPairCache,
} from '@sspiff/handy-keypair'
import getConfigFromTags from '@sspiff/handyaws/lambda/getConfigFromTags'
import getKeyValue from '@sspiff/handyaws/keyValue/get'
import {frontAuth as _frontAuth} from '../'


jest.mock('@sspiff/handyaws/lambda/getConfigFromTags', () => ({
    __esModule: true,
    default: jest.fn()
  }))

jest.mock('@sspiff/handyaws/keyValue/get', () => ({
    __esModule: true,
    default: jest.fn()
  }))


var TNOW = 0
var dateNowSpy = jest.spyOn(Date, 'now').mockImplementation(() => TNOW)


// from https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html#lambda-event-structure-request
const exampleEventRequest = () => {
  const event = {"Records": [
      {
        "cf": {
          "config": {
            "distributionDomainName": "d111111abcdef8.cloudfront.net",
            "distributionId": "EDFDVBD6EXAMPLE",
            "eventType": "viewer-request",
            "requestId": "4TyzHTaYWb1GX1qTfsHhEqV6HUDd_BzoBZnwfnvQc_1oF26ClkoUSEQ=="
          },
          "request": {
            "clientIp": "203.0.113.178",
            "headers": {
              "host": [
                {
                  "key": "Host",
                  "value": "d111111abcdef8.cloudfront.net"
                }
              ],
              "user-agent": [
                {
                  "key": "User-Agent",
                  "value": "curl/7.66.0"
                }
              ],
              "accept": [
                {
                  "key": "accept",
                  "value": "*/*"
                }
              ]
            },
            "method": "GET",
            "querystring": "",
            "uri": "/"
          }
        }
      }
    ]}
  return [event, event.Records[0].cf.request]
}


beforeEach(() => {
  jest.clearAllMocks()
  TNOW = 0
})


describe('frontAuth', () => {

  // key parameters
  const key = {
    type: 'ec',
    options: {namedCurve: 'prime256v1'},
    name: 'testkey',
    version: '1',
    expiresAt: 1000
  }
  const jwtSignOptions = { algorithm: 'ES256' }
  const jwtVerifyOptions = { algorithms: 'ES256' }

  // create our test key
  const keyPair = createKeyPair(key)
  const publicKey = publicKeyFromKeyPair(keyPair)

  // bind jwtSign to our key pair cache
  const sign = jwtSign.bind(new KeyPairCache({
      fetchKeyPairData: keyName => Promise.resolve(keyPair),
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000
    }))

  // mock lambda config
  const config = {
      keyPairName: 'testkey',
      publicKeyStore: 'test:///store/',
      setCookieUri: '/setcookie',
      tokenCookieName: 'testtoken',
      jwtVerifyOptions
    }
  getConfigFromTags.mockResolvedValue(config)

  // mock public key store
  const publicKeyUri = `${config.publicKeyStore}${key.name}/${key.version}`
  getKeyValue.mockResolvedValue(JSON.stringify(publicKey))

  // create our frontAuth handler
  const getSetCookieToken = jest.fn(request => request.body.token)
  const getAuthorizedPatterns = jest.fn(claims =>
    (['^/common/.*', `^/user/${claims.userid}/.*`]))
  const frontAuth = _frontAuth.bind({
      getSetCookieToken,
      getAuthorizedPatterns
    })
  const context = {
      invokedFunctionArn: 'arn:test'
    }

  // create test token
  const payload = {userid: 'testuser'}
  const tokenExpiresAt = 10 * 1000
  const getToken = sign(payload, key.name, {
      ...jwtSignOptions,
      expiresIn: Math.floor(tokenExpiresAt / 1000)
    })

  test('responds to set cookie', async () => {
    const [event, request] = exampleEventRequest()
    const token = await getToken
    request.uri = config.setCookieUri
    request.body = {token}
    const response = await frontAuth(event, context)
    expect(getSetCookieToken.mock.calls.length).toBe(1)
    expect(getSetCookieToken.mock.calls[0][0]).toBe(request)
    expect(getConfigFromTags.mock.calls.length).toBe(1)
    expect(getConfigFromTags.mock.calls[0][0]).toMatchObject({
      arn: context.invokedFunctionArn})
    expect(getKeyValue.mock.calls.length).toBe(1)
    expect(getKeyValue.mock.calls[0][0]).toBe(publicKeyUri)
    expect(response.status).toEqual('204')
    expect(response.headers).toMatchObject({
        'set-cookie': [{
          key: 'Set-Cookie',
          value: `${config.tokenCookieName}=${token}`
        }]
      })
  })

  test('set cookie response includes cookie config', async () => {
    const [event, request] = exampleEventRequest()
    const token = await getToken
    request.uri = config.setCookieUri
    request.body = {token}
    const altConfig = {
        ...config,
        tokenCookieConfig: 'Secure HttpOnly Path=/'
      }
    const altContext = {
        ...context,
        invokedFunctionArn: 'arn:altconfig'
      }
    getConfigFromTags.mockResolvedValueOnce(altConfig)
    const response = await frontAuth(event, context)
    expect(response.headers).toMatchObject({
        'set-cookie': [{
          key: 'Set-Cookie',
          value: `${config.tokenCookieName}=${token}; ${altConfig.tokenCookieConfig.split(' ').join('; ')}`
        }]
      })
  })

  test('forbidden if no token on set cookie', async () => {
    const [event, request] = exampleEventRequest()
    const token = await getToken
    request.uri = config.setCookieUri
    request.body = {}
    const response = await frontAuth(event, context)
    expect(response.status).toBe('403')
  })

  test('forbidden if bad token on set cookie', async () => {
    const [event, request] = exampleEventRequest()
    const token = await getToken
    request.uri = config.setCookieUri
    request.body = {token}
    var response = await frontAuth(event, context)
    expect(response.status).toBe('204')
    TNOW = tokenExpiresAt
    response = await frontAuth(event, context)
    expect(response.status).toBe('403')
  })

  test('allows on authorized pattern match', async () => {
    const [event, request] = exampleEventRequest()
    const token = await getToken
    // get cookie settings
    request.uri = config.setCookieUri
    request.body = {token}
    var response = await frontAuth(event, context)
    delete request.body
    request.headers['cookie'] = [{
        key: 'Cookie',
        value: response.headers['set-cookie'][0].value
      }]
    // now submit request
    request.uri = '/common/test'
    response = await frontAuth(event, context)
    expect(getSetCookieToken.mock.calls.length).toBe(1)
    expect(getConfigFromTags.mock.calls.length).toBe(2)
    expect(getKeyValue.mock.calls.length).toBe(0)  // cached
    expect(getAuthorizedPatterns.mock.calls.length).toBe(1)
    expect(getAuthorizedPatterns.mock.calls[0][0]).toMatchObject(payload)
    expect(response).toBe(request)
    // try another one
    request.uri = `/user/${payload.userid}/foo`
    response = await frontAuth(event, context)
    expect(response).toBe(request)
  })

  test('forbidden on no pattern match', async () => {
    const [event, request] = exampleEventRequest()
    const token = await getToken
    // get cookie settings
    request.uri = config.setCookieUri
    request.body = {token}
    var response = await frontAuth(event, context)
    delete request.body
    request.headers['cookie'] = [{
        key: 'Cookie',
        value: response.headers['set-cookie'][0].value
      }]
    // submit request
    request.uri = '/user/someotheruser/foo'
    response = await frontAuth(event, context)
    expect(response.status).toBe('403')
  })

  test('forbidden if no token cookie', async () => {
    const [event, request] = exampleEventRequest()
    // submit request
    request.uri = '/common/foo'
    const response = await frontAuth(event, context)
    expect(response.status).toBe('403')
  })

  test('forbidden if bad token cookie', async () => {
    const [event, request] = exampleEventRequest()
    const token = await getToken
    // get cookie settings
    request.uri = config.setCookieUri
    request.body = {token}
    var response = await frontAuth(event, context)
    delete request.body
    request.headers['cookie'] = [{
        key: 'Cookie',
        value: response.headers['set-cookie'][0].value
      }]
    // submit request
    request.uri = '/common/foo'
    response = await frontAuth(event, context)
    expect(response).toBe(request)
    // now timeout the token
    TNOW += tokenExpiresAt
    response = await frontAuth(event, context)
    expect(response.status).toBe('403')
  })

})

