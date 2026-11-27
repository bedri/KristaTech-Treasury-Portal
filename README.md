# KristaTech Treasury Portal

Zero-custody Layer-1 Developer Fund governance & H+1 LLMQ Quorum signing web portal for **KristaTech (`KRISTA`)**, aligned with **KristaTech Core v1.5.9.0** (`PROTOCOL_VERSION = 70983`, `KTDIP3`, `UPGRADE_FAIRNESS` Balanced Model D, `Hardening_v3`, and `Hardening_v4`).

## Setup & Commands

```bash
npm install
npm run dev      # Local dev server on http://127.0.0.1:3000
npm run build    # Production Nitro/Nuxt build
npm run preview  # Preview production build on 127.0.0.1:3000
npm test         # Run cryptographic, security, i18n, and XSS surface tests
```

### Environment Variables & RPC Discovery

By default, the server resolves `kristatechd` JSON-RPC settings from environment variables or falls back to `~/.kristatech/kristatech.conf` (`rpcuser`, `rpcpassword`, `rpcport`, `rpcconnect`) and `~/.kristatech/.cookie`:

- `NUXT_RPC_USER` / `NUXT_RPC_PASSWORD`: JSON-RPC Basic Auth credentials.
- `NUXT_RPC_URL`: Full `http://` or `https://` RPC endpoint (defaults to `http://127.0.0.1:27998`).
- `NUXT_ALLOW_INSECURE_REMOTE_RPC`: Set to `'true'` only if plaintext `http://` to a non-loopback host is intentionally used (otherwise rejected fail-closed; prefer `https://` or an SSH tunnel).
- `NUXT_PROPOSALS_FILE`: Optional path for the atomic proposal store (defaults to `./proposals.json`, written with `0o600` permissions).
- `NUXT_TRUST_PROXY`: Set to `'true'` only behind a trusted local/private reverse proxy when honoring `X-Real-IP` / `X-Forwarded-For`.
- `NUXT_ENABLE_DEVTOOLS`: Set to `'true'` to enable Nuxt DevTools (disabled by default).

## Consensus Alignment (`Hardening_v3` & `Hardening_v4`)

- **Dynamic LLMQ Quorum & `2/3+1` BFT Supermajority (`UPGRADE_HARDENING_V4`):**
  Quorum size scales with active on-chain Masternodes (`GetTargetQuorumSize`), and signature thresholds enforce `min(N, max(2, floor(2N / 3) + 1))` (`GetQuorumThreshold`):
  - `< 25` active MNs → `5` members (`4/5` BFT supermajority)
  - `25–49` active MNs → `9` members (`7/9` BFT supermajority)
  - `50–99` active MNs → `11` members (`8/11` BFT supermajority)
  - `>= 100` active MNs → `15` members (`11/15` BFT supermajority)
  - Max `1` quorum seat per unique KTDIP3 BLS operator key; when `< 5` active MNs exist, all real MNs are preserved and deficits fill from the quota-capped ADAM fallback pool.
- **Domain-Separated BLS12-381 Treasury Signatures (`UPGRADE_HARDENING_V3`):**
  All treasury `CBLSSignedData` signatures (145B pure KTDIP3 Operator BLS via `SignBLSOperatorOnly` / `DeriveBLSFromCKey`, or 209B+ hybrid BLS+ECDSA) and aggregated quorum verifications use the dedicated Treasury DST:
  `BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_KRISTA_LLMQ_TREASURY_V1_"`
  Legacy un-domained signatures (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`) are strictly rejected.
- **`45s` Anti-Equivocation Window:** `QUORUM_EQUIVOCATION_GUARD_SECS = 45` (matching `src/llmq.h`).
- **Balanced Model D (`UPGRADE_FAIRNESS` + `Hardening_v4`):**
  `15` committee seats (`8` MN + `2` Coin-Lock + `3` PoW-Lock + `2` Free Entry `0` KRISTA) with `60% / 15 = 4.00%` equal seat payout, `ADAM_FAIR_COORD_V5` (`>=55%` active MN VRF floor), `10%` signer-only LLMQ rewards with V4 `M-4` PoSe (`-5` recovery for signers without LLMQ omission penalty; `+5` for silent primary ADAM/coordinators), `5%` passive MN, `25%` producer (`22%` staker + `3%` coordinator in PoS), and `50/50` unclaimed burn/treasury split.

## Security Model & V4 Remote RPC (`IsAllowedHTTPRequestHost`)

- **Zero-Custody Browser Signing:** WIF and 64-hex KTDIP3 BLS operator keys stay strictly in browser memory, sign locally (`secp256k1` low-S + `BLS12-381`), and temporary secret buffers are zero-filled in `finally` blocks.
- **Server Hardening:** Strict RPC method allowlist (`ALLOWED_RPC_METHODS`), per-request CSP nonces, `Sec-Fetch-Site` isolation, rate limiting, TOCTOU mutex locking on `proposals.json` (`0o600`), and credential/path/endpoint redaction (`sanitizeRpcErrorMessage`).
- **V4 `IsAllowedHTTPRequestHost` (`403 Forbidden`) for Remote RPC:**
  Under `Hardening_v4`, `kristatechd` blocks HTTP RPC requests with untrusted `Host` headers to prevent DNS-rebinding attacks (`403 Forbidden`). For remote RPC connections, configure `NUXT_RPC_URL` using a **numeric IP literal** (e.g., `https://198.51.100.10:27998`) or **`localhost` / `127.0.0.1` / `[::1]`** (e.g., over an SSH tunnel), **or** pass `-rpcbind=<hostname>` to `kristatechd` so the hostname is explicitly allowlisted.
