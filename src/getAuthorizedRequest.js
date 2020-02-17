
import parseCookies from '@sspiff/handyaws/lambdaEdge/parseCookies'


/*
 *
 * @function getAuthorizedRequest
 * @memberof module:@sspiff/handyaws-frontauth
 * @param {Object} event - Lambda@Edge handler event
 */
export default function (event) {
  const request = event.Records[0].cf.request
  const token = parseCookies(request.headers)[this.tokenCookieName]
  return (
    this.getAuthorizedPatterns(token)
    .then(patterns => {
        if (patterns.some(re => (new RegExp(re)).test(request.uri)))
          return request
        else
          throw 'EACCES'
      })
  )
}

