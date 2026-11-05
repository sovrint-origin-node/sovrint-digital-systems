/** Historical UI placeholder; must never mint an identity or authorization token. */
export function TokenMint(author, lineage, timestamp = new Date().toISOString()) {
  return Object.freeze({
    token: null,
    author: typeof author === 'string' ? author : null,
    lineage: typeof lineage === 'string' ? lineage : null,
    mintedAt: null,
    requestedAt: timestamp,
    verified: false,
    issued: false,
    reason: 'SIGNING_AUTHORITY_NOT_CONFIGURED'
  });
}
