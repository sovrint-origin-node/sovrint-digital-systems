/** Prefix checking is not a signature or authorization check. */
export function TokenValidator(token) {
  return Object.freeze({
    token: typeof token === 'string' ? token : null,
    valid: false,
    verified: false,
    reason: 'ISSUER_SIGNATURE_EXPIRY_AUDIENCE_NOT_VERIFIED',
    timestamp: new Date().toISOString()
  });
}
