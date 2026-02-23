// Compliance Mapping Service
// Re-exports from compliance-core shared module for backwards compatibility.
// New code should import from './compliance-core' directly.

export {
  seedFrameworks,
  getFrameworkCompliance,
  getGapAnalysis,
  listFrameworks,
  upsertMapping,
} from './compliance-core';
