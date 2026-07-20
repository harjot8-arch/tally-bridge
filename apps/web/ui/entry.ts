/**
 * Bundle entry for dist/tally-data.js — the data layer's public API plus the two viewmodel
 * formatters the UI needs (`formatMoney` for the bank/cash split it derives itself,
 * `formatDelta` for the month-over-month sales line).
 *
 * Why not the built-in 'en-IN' number formatter in the UI: without full ICU it silently
 * falls back to en-US grouping and prints ₹1,42,34,110 as ₹14,234,110 (ARCHITECTURE.md
 * pins this). `formatMoney` is the hand-rolled Indian grouping every surface shares.
 */
export * from '../src/data/index.ts';
export { formatMoney, formatDelta } from '@tally-bridge/viewmodel';
