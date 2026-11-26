/**
 * The wire-level action enum for `rea_reconstruct`. Kept in one dependency-free
 * module so the tool schema, runtime validation, gap metadata and host-matrix
 * all read the same list.
 *
 * @module dsh-rea-restore/lib/recon-actions
 */

export const RECONSTRUCT_ACTIONS = Object.freeze([
  'start', 'advance', 'status', 'handoff', 'rewrite',
  'dynamic-plan', 'dynamic-apply', 'unpack-apply', 'dump-apply', 'trace-apply',
  'hypothesis-record', 'hypothesis-check',
]);