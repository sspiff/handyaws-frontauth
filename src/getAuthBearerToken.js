
/**
 * Use as `this.getSetCookieToken` with
 * {@link module:@sspiff/handyaws-frontauth.frontAuth frontAuth}
 * to extract the token from the `Authorization` header (with the
 * `Bearer` scheme).
 *
 * @function getAuthBearerToken
 * @memberof module:@sspiff/handyaws-frontauth
 */
export default request => {
  const [scheme, token] = request.headers.authorization[0].value.split(' ')
  if (scheme === 'Bearer')
    return token
  else
    throw 'EINVAL'
}

