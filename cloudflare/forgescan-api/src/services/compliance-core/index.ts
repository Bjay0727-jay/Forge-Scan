// ─────────────────────────────────────────────────────────────────────────────
// Compliance Core — Shared Compliance Framework Module
// Used by ForgeScan (compliance service) and ForgeRedOps (auto-POA&M)
// ─────────────────────────────────────────────────────────────────────────────

export { FRAMEWORKS, type FrameworkDef, type ControlDef } from './frameworks';
export {
  seedFrameworks,
  getFrameworkCompliance,
  getGapAnalysis,
  listFrameworks,
  upsertMapping,
} from './queries';
export {
  mapFindingToControls,
  mapCWEToNISTControls,
  mapCWEToCISControls,
  generatePOAMEntry,
  type POAMEntry,
  type ControlMapping,
} from './mapping';
