/** Chart descriptor, not a renderer; no plot is produced by this function. */
export function GraphRenderer(equation, domain) {
  return Object.freeze({equation, domain, rendered: false, status: 'DESCRIPTION_ONLY', timestamp: new Date().toISOString()});
}
