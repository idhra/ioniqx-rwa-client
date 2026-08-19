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

The five Anchor programs are not yet deployed, so `idl/` is empty and
`Config::PROGRAM_IDS` is unpopulated. The transfer-hook resolver and the
classification reader are complete, with golden-vector specs that run offline.

## Install

```ruby
gem "ioniqx-rwa-client"
```

## Transfer-hook resolution

```ruby
rpc      = Solana::Ruby::Kit::Rpc::Client.new(url: "https://api.devnet.solana.com")
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
