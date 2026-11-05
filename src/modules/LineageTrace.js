/** Local visualization of caller-supplied mappings, NOT a cryptographic lineage seal. */
export function LineageTrace(origin, rerouteMap) {
  const safe = rerouteMap !== null && typeof rerouteMap === 'object' && !Array.isArray(rerouteMap)
    ? Object.entries(rerouteMap).filter(([key]) => key !== '__proto__') : [];
  const trace = safe.map(([jurisdiction, vector], index) => ({
    node: `Trace-${index + 1}`, jurisdiction, vector,
    timestamp: new Date().toISOString()
  }));
  return Object.freeze({origin, trace, sealed: false, provenanceVerified: false, status: 'UNVERIFIED_SIMULATION'});
}
