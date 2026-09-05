# ioniqx-rwa-client

Ruby client for the [ioniqx](https://ioniqx.io) RWA on-chain program suite.

Built **on top of** [`solana-ruby-kit`](https://github.com/pzupan/solana-ruby-kit),
the 1-to-1 Ruby port of `@anza-xyz/kit`. The kit already owns transport, codecs,
PDA derivation, transaction assembly, and signing — this gem does not
reimplement any of it. It adds only the layer the kit has no notion of:

1. **Anchor instruction discriminators** — `sha256("global:<name>")[0,8]`.
2. **IDL → instruction mapping** — arg codecs and ordered account metas, driven
   off the IDLs committed in `idl/`.
3. **Transfer-hook `ExtraAccountMetaList` resolution** — `extra_account_metas.rb`.
4. **Thin instruction builders** for the five ioniqx programs.
5. **Classification reader** — read-side sRFC RWA classification metadata and
   attestation parsing. Descriptive only; never consulted for authorization.

## Status

**Unaudited. Not for production.** See [SECURITY.md](SECURITY.md).

The five Anchor programs are not yet deployed to a public cluster, so `idl/` is
empty and `Config::PROGRAM_IDS` is unpopulated. Hook-aware transfer
construction, the transfer-hook resolver, and the classification reader are
complete, with specs that run offline — including one pinned against an account
list `ioniqx-transfer-restrictions` itself produced and Token-2022 accepted.

## Install

```ruby
gem "ioniqx-rwa-client"
```

## Transferring a hook-gated token

BUILD.md §2.7 Section 4.3: *"Every client that transfers this token MUST build
the instruction with hook-aware resolution. A plain `transferChecked` will omit
the extra accounts and fail."*

That failure is not obvious when it happens — Token-2022 cannot invoke the hook
without the accounts, so the transaction aborts complaining about a missing
account, naming nothing about the hook. Use this and it is handled:

```ruby
rpc      = Solana::Ruby::Kit::Rpc::Client.new(url: "https://api.devnet.solana.com")
transfer = IoniqxRwa::Transfer.new(rpc)

instruction = transfer.transfer_checked(
  mint:        mint_address,
  source:      source_token_account,
  destination: destination_token_account,
  authority:   owner_address,
  amount:      1_000
)
```

The hook program id, the mint's decimals, and the token program that owns the
mint are all read off the mint rather than taken as arguments; each is
something a caller can get wrong in a way that only shows up as a rejected
transaction. A mint that declares no hook gets a plain four-account transfer,
so every SPL transfer can be routed through this without branching on which
mints happen to be restricted.

That includes original-SPL-Token mints. ioniqx issues its own tokens under
Token-2022, because that is where transfer hooks live, but nothing follows from
that about the mints it has to *move*: USDC, the settlement asset, is a
`TokenkegQ…` mint on every cluster. The instruction goes to whichever program
owns the mint, and a mint owned by neither token program is refused rather than
guessed at.

Pass `token_program_id:`, `hook_program_id:` or `decimals:` explicitly to
override what the mint says. A caller that has already read the mint — which it
generally has, since associated token accounts are derived under the mint's own
program — can pass `mint_info:` to skip the second read:

```ruby
info = transfer.mint_info(mint_address)
ata  = # ...derive under info.token_program_id...

transfer.transfer_checked(mint: mint_address, source: ata, ..., mint_info: info)
```

### Commitment

Every account read this gem makes goes out at `confirmed`, not at the RPC's own
`finalized` default. The accounts it reads are ones the caller was just handed —
the mint being transferred, the validation account written when that mint was
configured — and finality is roughly 32 slots behind the tip, so a finalized
read of a mint issued seconds ago returns nothing and the caller sees
`account not found` for an account that plainly exists.

```ruby
IoniqxRwa::Transfer.new(rpc, commitment: :finalized)  # slower, stricter
IoniqxRwa::Transfer.new(rpc, commitment: nil)         # send none; endpoint decides
```

`ExtraAccountMetas` and `Classification::Reader` take the same argument, and a
`Transfer` passes its own down to the resolver it builds.

### Resolving the extra accounts directly

If you are assembling the transfer instruction yourself:

```ruby
resolver = IoniqxRwa::ExtraAccountMetas.new(rpc)

extras = resolver.resolve(
  mint:            mint_address,
  source:          source_token_account,
  destination:     destination_token_account,
  authority:       owner_address,
  amount:          1_000,
  hook_program_id: transfer_restrictions_program_id
)
```

Append `extras` to the transfer instruction's account list after the standard
transfer accounts. The returned array is the resolved extra accounts followed by
`[hook_program, validation_account]`; each entry is a plain Hash carrying
`:pubkey`, `:writable`, `:signer` — convert to the kit's `AccountMeta` at
instruction-assembly time.

## Classification (read-side only)

Reads the sRFC RWA classification convention: `rwa.*` mint metadata (Layer 1),
the SAS attestation (Layer 2), and the signed discovery document (Layer 3).

```ruby
C = IoniqxRwa::Classification

parsed = C.parse(mint_additional_metadata)       # => ParseResult
view   = C::Reader.new(rpc).attestation_for(     # derived, no indexer
           mint: mint, credential: transfer_agent_credential)

trust = C.resolve_trust(
  mint:              mint,
  classification:    parsed.classification,
  attestation:       view,
  trusted_attesters: [transfer_agent_credential],  # your policy, not ours
  mint_authorities:  [issuer_authority]
)

C.trust_label(trust.level)          # => "Verified"
C.describe(parsed.classification)   # => "Multifamily · Equity"
```

**This is descriptive, not enforcing.** Per §5 of the draft, no value returned
here may be used for authorization, transfer eligibility, or compliance
decisions — those live on-chain in the token's own extensions. Nothing in this
module touches the transfer path.

Two details worth knowing: trust is keyed on the **credential**, not the
attestation's `signer`, because authorized signers rotate freely; and a revoked
attestation is byte-for-byte identical to one that never existed, so **expiry,
not revocation, is the load-bearing control**.

The attestation address derives from `(credential, schema, mint)` alone, so
`rwa.attestation` in the metadata is a hint and never the authority.

## Issuance (write side)

Encodes a `rwa.classification.v1` payload and builds the SAS `createAttestation`
instruction that carries it. Layer 1 (the `rwa.*` mint metadata) is written by
the mint creation path, not here.

```ruby
result = IoniqxRwa::Classification::Issuance.attest(
  payer: payer, authority: authorized_signer,
  credential: transfer_agent_credential, schema: schema_pda,
  mint: mint, expires_at: 90.days.from_now.to_i,
  asset_class: "real-estate", claim: "equity", subclass: "multifamily",
  jurisdiction: "US-TX", issuer_lei: lei,
  property_commit: commit, discovery_url: url, discovery_signer: signing_key
)

result[:instruction]   # append to a transaction
result[:attestation]   # the address it will create
```

Expiry is mandatory and short by design: revocation deletes the account and is
indistinguishable from absence, so lapse — not revocation — is the real control.
The draft also warns the attester SHOULD NOT be the issuer; self-attestation is
permitted but must be detectable, which `resolve_trust` surfaces.

## Tests

```bash
bundle exec rspec              # hermetic, no network
IONIQX_GOLDEN_DEVNET=1 bundle exec rspec   # + devnet parity vs. the TS reference
```

The offline suite uses golden vectors and a fake RPC, so encode correctness is
verifiable with zero network access. The devnet parity test is opt-in and
asserts byte-identical output against the `@solana/kit` + `spl-transfer-hook`
TypeScript reference.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for design lineage.
