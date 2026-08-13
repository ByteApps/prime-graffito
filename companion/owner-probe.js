// Shared by index.html and its node test (tests/test_owner_probe.js):
// probe ONE spending-wallet watch-list address for its current UTXOs
// (tagged `owner_address`, same shape the mixed-compose e2e already
// exercises) AND whether it has ANY on-chain history at all.
//
// This is the companion half of gap-discovery option (b)
// (PLAN-chain-notes-funding-unification.md, 2026-07-19): the device
// exports a lookahead WATCH WINDOW (Settings' spending card — next 20
// receive + next 20 change addresses) instead of only its already-`used`
// addresses. Most of those window addresses are still unused, but a
// spent-then-emptied one has zero UTXOs and would otherwise look
// identical to "never touched" — the device needs to tell the two apart
// so its own next_receive/next_change bookkeeping converges past an
// address it already spent, instead of re-offering it as "next receive"
// forever. `used: true` is exactly that signal; index.html collects it
// across the whole watch list into the bundle's additive `owner_used`
// field (see prime-graffito CLAUDE.md's "spending-adopt … used-only"
// log line, and notes-core::bundle::SyncBundle.owner_used).
//
// Deliberately dependency-light (companion stays crypto-free): no
// BIP-32/secp256k1/bech32 here, just two esplora-shaped fetches through
// the caller's own `apiJson(path)` helper (index.html's real one hits
// mempool.space or the local regtest shim; tests pass a stub) — this
// module never talks to the network itself and never derives an address,
// it only asks "does this literal address the device already told us
// about have a coin, and/or has it ever had one?"
"use strict";

/**
 * @param {(path: string) => Promise<any>} apiJson - GET + JSON-parse an
 *   esplora-shaped path (`/address/:a/utxo`, `/address/:a/txs`) against
 *   whichever network base the caller has selected.
 * @param {string} address
 * @returns {Promise<{utxos: object[], used: boolean}>} `utxos` are the
 *   address's current UTXOs, each with `owner_address` set to `address`
 *   (same tagging the bundle's `utxos[].owner_address` field expects);
 *   `used` is true iff `/txs` returned any tx at all (funded, spent, or
 *   both) — independent of whether a coin remains.
 */
async function probeOwnerAddress(apiJson, address) {
  const [utxos, history] = await Promise.all([
    apiJson(`/address/${address}/utxo`),
    apiJson(`/address/${address}/txs`),
  ]);
  return {
    utxos: utxos.map((u) => ({ ...u, owner_address: address })),
    used: history.length > 0,
  };
}

if (typeof module === "object" && module.exports) {
  module.exports = { probeOwnerAddress };
}
