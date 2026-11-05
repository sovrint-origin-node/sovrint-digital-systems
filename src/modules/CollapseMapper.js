/** Historical collapse diagnostic descriptor; no live telemetry is connected. */
export function CollapseMapper(layer, collapseMode) {
  return Object.freeze({layer, collapseMode, status: 'SIMULATED_NOT_LIVE', timestamp: new Date().toISOString()});
}
