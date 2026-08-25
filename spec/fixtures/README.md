# Golden fixtures

## `client_resolution.json`

The account list a hook-aware client must produce for one real transfer, plus
the on-chain bytes it has to read to get there.

Emitted by `hook_transfer.rs::emits_the_client_resolution_fixture` in the
[ioniqx-rwa](https://github.com/pzupan/ioniqx-rwa) workspace, which runs the
real Token-2022, the real Solana Attestation Service, and the ioniqx transfer
hook in LiteSVM, performs a transfer that succeeds, and records the accounts
the Rust resolver produced.

`spec/client_resolution_spec.rb` replays it: same on-chain state in, same
account list out. This is what proves the Ruby resolver agrees with the program
rather than merely with itself — hand-built validation buffers cannot catch
both sides sharing a wrong reading of the TLV format.

To refresh after changing the hook's declared accounts:

```bash
cd ioniqx-rwa
anchor build -p ioniqx-transfer-restrictions
UPDATE_FIXTURES=1 cargo test -p ioniqx-transfer-restrictions --test hook_transfer
cp tests/fixtures/client_resolution.json ../ioniqx-rwa-client/spec/fixtures/
```

The Rust test fails rather than silently rewriting the file when the two drift,
so a stale copy here is visible from either side.
