/** Historical SOVRINT root-certificate demonstration. No cryptographic authority is issued. */
export function RootCertManager(author, jurisdiction) {
  const label = typeof author === 'string' ? author.replace(/\s+/g, '') : '';
  return Object.freeze({
    certificate: label ? `SOVRINT.${label}.root` : null,
    jurisdiction: typeof jurisdiction === 'string' ? jurisdiction : null,
    verified: false,
    status: 'UNVERIFIED_SIMULATION',
    reason: 'NO_SIGNATURE_OR_TRUST_CHAIN',
    timestamp: new Date().toISOString()
  });
}
