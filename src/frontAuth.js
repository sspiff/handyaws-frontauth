
import {jwtVerify, PublicKeyCache} from '@sspiff/handy-keypair'
import getConfigFromTags from '@sspiff/handyaws/lambda/getConfigFromTags'
import getKeyValue from '@sspiff/handyaws/keyValue/get'
import getAuthorizedRequest from './getAuthorizedRequest'
import setCookieResponse from './setCookieResponse'


/**
 * Implements an AWS CloudFront Lambda@Edge viewer request handler that
 * rejects unauthorized requests based on a JSON web token passed from the
 * client as an HTTP cookie and the requested URI.  Includes a simple client
 * API to assist in setting the cookie for browser clients.
 *
 * If authorization fails for any reason, `frontAuth()` returns
 * 403 Forbidden to the client.
 *
 * ##### Token Verification
 *
 * `frontAuth()` uses {@link module:@sspiff/handy-keypair @sspiff/handy-keypair}
 * to decode and verify the JSON web token, with
 * {@link module:@sspiff/handyaws.keyValue/get @sspiff/handyaws/keyValue/get}
 * as the public key store.
 *
 * The public key URI is constructed as
 * `` `${cfg.publicKeyStore}${cfg.keyPairName}/${keyVersion}` `` (where
 * `keyVersion` comes from the token).
 *
 * ##### Request URI Matching
 *
 * In addition to the token, requests must match one of a dynamic set of
 * path patterns.  After the token is decoded and verified,
 * `this.getAuthorizedPatterns()` is called with the token payload.
 * It should return an array of uncompiled regular expression strings that
 * define the URIs authorized by the token.  If the requested URI matches
 * any one, the request will be accepted.
 *
 * ##### Set Cookie API
 *
 * To assist browser clients in setting the authorization cookie for the
 * CloudFront distribution host, a simple set cookie API is provided.
 * First, clients should obtain their token using another application
 * API (such as via API Gateway backed by Lambda).  Then, clients can `POST`
 * their token to the URI specified by `cfg.setCookieUri` to receive the
 * required `Set-Cookie` HTTP response headers.
 *
 * When `frontAuth()` receives a `POST` request for `cfg.setCookieUri`,
 * it will call `this.getSetCookieToken()` with the Lambda@Edge event
 * request object.  `this.getSetCookieToken()` should extract the token
 * from the request and return it.  `frontAuth()` will then build a response
 * object that sets the cookie value to the token.
 *
 * ##### Bound this
 *
 * In addition to the configuration values described below, `frontAuth()`
 * requires the two helper functions, `this.getAuthorizedPatterns()` and
 * `this.getSetCookieToken()`, described above.  These helper functions
 * should be placed in an object and that object bound to `frontAuth()`
 * (or used with `frontAuth.call()`).  See the example.
 *
 * ##### Configuration
 *
 * Besides the helper functions in the bound `this`, `frontAuth()` fetches
 * it's configuration from the AWS resource tags on the Lambda function itself.
 * Tags are used because Lambda@Edge functions cannot use environment
 * variables.  The following tags can be defined on the Lambda function
 * resource:
 *
 * | Tag                      | Description                           |
 * | ------------------------ | ------------------------------------- |
 * | `cfg.jwtVerifyOptions.*` | Options for `jwt.verify()`            |
 * | `cfg.keyPairName`        | Name of key pair used to verify token |
 * | `cfg.publicKeyStore`     | Base URI for the public key store     |
 * | `cfg.setCookieUri`       | Relative URI for setCookie interface  |
 * | `cfg.tokenCookieConfig`  | Cookie configuration appended to `Set-Cookie` response, use spaces to separate directives instead of `;` |
 * | `cfg.tokenCookieName`    | Name of HTTP cookie containing token  |
 *
 * Notes on `cfg.jwtVerifyOptions`:
 *
 * | Option           | Notes                                              |
 * | ---------------- | -------------------------------------------------- |
 * | `algorithms`     | Separate multiple algorithms with spaces           |
 * | `clockTolerance` | Will be converted to an integer using `parseInt()` |
 * | `maxAge`         | Is not swizzled, so use e.g. `10s` for seconds     |
 *
 * @function frontAuth
 * @memberof module:@sspiff/handyaws-frontauth
 * @param {Object} event - Lambda@Edge event object
 * @param {Object} context - Lambda@Edge context object
 *
 * @example
 * import {frontAuth, getAuthBearerToken} from '@sspiff/handyaws-frontauth'
 *
 * // example lambda function tags:
 * // cfg.jwtVerifyOptions.algorithms     'ES256'
 * // cfg.keyPairName                     'myKeyPair'
 * // cfg.publicKeyStore                  'ssm://us-east-1/keyStore/'
 * // cfg.setCookieUri                    '/setcookie'
 * // cfg.tokenCookieName                 'myAuth'
 * // cfg.tokenCookieConfig               'Secure HttpOnly Path=/'
 *
 * // in this example, a valid token grants access to any request.uri
 * // starting with '/common/' or '/user/USERID/', where USERID comes from
 * // the token claims:
 * const getAuthorizedPatterns = claims =>
 *   (['^/common/.*', `^/user/${claims.userid}/.*`])
 *
 * export const handler = frontAuth.bind({
 *     getSetCookieToken: getAuthBearerToken,
 *     getAuthorizedPatterns
 *   })
 */
export default async function (event, context) {
  try {
    // get config
    const config = await getConfigFromTags({
        arn: context.invokedFunctionArn,
        prefix: 'cfg.',
        sep: '.',
        retryFirstDelay: 500,
        retryMaxDelay: 120000
      })
    // swizzle jwtVerifyOptions
    const jwtVerifyOptions = config.jwtVerifyOptions
    if (jwtVerifyOptions) {
      if (jwtVerifyOptions.clockTolerance &&
          typeof config.clockTolerance === 'string')
        jwtVerifyOptions.clockTolerance = parseInt(jwtVerifyOptions.clockTolerance)
      if (jwtVerifyOptions.algorithms &&
          typeof jwtVerifyOptions.algorithms === 'string')
        jwtVerifyOptions.algorithms = jwtVerifyOptions.algorithms
          .trim()
          .split(' ')
    }
    // add jwtVerify
    if (!config.jwtVerify)
      config.jwtVerify = jwtVerify.bind(new PublicKeyCache({
          maxCacheEntries: 1,
          retryFirstDelay: 500,
          retryMaxDelay: 120000,
          fetchPublicKeyData: (keyName, keyVersion) => {
              const u = new URL(config.publicKeyStore)
              u.pathname += `${keyName}/${keyVersion}`
              return getKeyValue(u.toString())
                .then(json => JSON.parse(json))
            }
        }))
    // process request
    const request = event.Records[0].cf.request
    if (config.setCookieUri && this.getSetCookieToken &&
        request.uri === config.setCookieUri) {
      const token = this.getSetCookieToken(request)
      const cookieConfig =
        (config.tokenCookieConfig || '').trim().split(' ').join('; ')
      await config.jwtVerify(token, config.keyPairName, config.jwtVerifyOptions)
      return setCookieResponse({
          token,
          cookieConfig,
          cookieName: config.tokenCookieName
        })
    }
    else {
      return await getAuthorizedRequest.call({
          tokenCookieName: config.tokenCookieName,
          getAuthorizedPatterns: token =>
            config.jwtVerify(token, config.keyPairName, config.jwtVerifyOptions)
            .then(claims => this.getAuthorizedPatterns.call(config, claims))
        }, event)
    }
  }
  catch (err) {
    return {
      status: '403',
      statusDescription: 'Forbidden'
    }
  }
}

