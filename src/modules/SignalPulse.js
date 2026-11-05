/** Demonstration score; the result is not an authenticated integrity metric. */
export function SignalPulse(frequency, signalStrength) {
  const numeric = typeof frequency === 'number' && Number.isFinite(frequency)
    && typeof signalStrength === 'number' && Number.isFinite(signalStrength);
  return Object.freeze({
    frequency, signalStrength,
    integrity: null, integrityVerified: false,
    simulatedScore: numeric ? Math.max(0, Math.min(100, frequency * signalStrength)) : null,
    status: 'UNVERIFIED_SIMULATION', timestamp: new Date().toISOString()
  });
}
