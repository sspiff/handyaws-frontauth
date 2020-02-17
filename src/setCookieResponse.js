
/*
 *
 * @function setCookieResponse
 * @memberof module:@sspiff/handyaws-frontauth
 *
 */
export default function ({cookieName, cookieConfig, token}) {
  cookieConfig = (cookieConfig && `; ${cookieConfig}`) || ''
  return ({
    status: '204',
    statusDescription: 'OK',
    headers: {
      'set-cookie': [{
        key: 'Set-Cookie',
        value: `${cookieName}=${token}${cookieConfig}`
      }]
    }
  })
}

