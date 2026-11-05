/** Historical override text generator. No institutional action is executed. */
export function OverrideClause(actor, breachType) {
  const a = typeof actor === 'string' ? actor.replace(/\s+/g, '') : '';
  const b = typeof breachType === 'string' ? breachType.toUpperCase() : '';
  return Object.freeze({
    clause: a && b ? `OVERRIDE.${a}.${b}` : null,
    breachType: typeof breachType === 'string' ? breachType : null,
    injected: false,
    authorized: false,
    status: 'PROPOSAL_ONLY',
    timestamp: new Date().toISOString()
  });
}
