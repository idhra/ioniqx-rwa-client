# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"
require "json"
require "base64"
require "ioniqx_rwa_client/transfer"

# Cross-language agreement with the ioniqx transfer hook.
#
# The offline vectors in extra_account_metas_spec.rb prove the resolver against
# validation buffers this repo builds itself, which cannot catch the two of us
# agreeing on a wrong reading of the format. This spec resolves against bytes
# the *program* produced: `spec/fixtures/client_resolution.json` is emitted by
# `hook_transfer.rs::emits_the_client_resolution_fixture` in ioniqx-rwa, which
# runs the real Token-2022, the real SAS program, and the hook in LiteSVM, does
# a transfer that succeeds, and records the account list the Rust resolver
# produced along with every account byte a client must read to get there.
#
# So the assertion is: given the same on-chain state, Ruby produces the account
# list Token-2022 accepted. Nothing weaker would tell us the Rails app can
# transfer these tokens.
#
# The ioniqx hook exercises the awkward corner of the format on purpose: the
# two attestation accounts are PDAs of an *external* program (SAS, itself a
# resolved extra) whose seeds are `AccountData` reads into the offering config
# — which is also a resolved extra, not one of the five accounts the resolution
# starts with. A resolver that only handles seeds pointing at the initial five
# gets this mint wrong.
RSpec.describe "hook-aware transfer construction" do
  FIXTURE = JSON.parse(
    File.read(File.expand_path("fixtures/client_resolution.json", __dir__))
  )

  let(:accounts) do
    FIXTURE["account_data"].each_with_object({}) do |(pubkey, b64), store|
      store[pubkey] = Base64.decode64(b64)
    end
  end

  let(:rpc)      { SpecSupport::FakeRpc.new(accounts) }
  let(:transfer) { IoniqxRwa::Transfer.new(rpc) }

  def expected_accounts = FIXTURE["accounts"]

  def actual(instruction)
    instruction.accounts.map do |m|
      role = m.role
      roles = Solana::Ruby::Kit::Instructions::AccountRole
      {
        "pubkey"      => m.address.to_s,
        "is_signer"   => [ roles::READONLY_SIGNER, roles::WRITABLE_SIGNER ].include?(role),
        "is_writable" => [ roles::WRITABLE, roles::WRITABLE_SIGNER ].include?(role)
      }
    end
  end

  def build
    transfer.transfer_checked(
      mint:        FIXTURE["mint"],
      source:      FIXTURE["source"],
      destination: FIXTURE["destination"],
      authority:   FIXTURE["authority"],
      amount:      FIXTURE["amount"]
    )
  end

  it "produces the account list the on-chain transfer accepted" do
    expect(actual(build)).to eq(expected_accounts)
  end

  it "produces the same instruction data" do
    expect(Base64.strict_encode64(build.data)).to eq(FIXTURE["instruction_data_base64"])
  end

  it "targets the token program" do
    expect(build.program_address.to_s).to eq(FIXTURE["token_program_id"])
  end

  # Guards the specific thing that made this worth checking: the attestation
  # PDAs are derived through account data belonging to an account resolved one
  # step earlier in the same pass.
  it "resolves accounts seeded from a previously-resolved extra account" do
    resolved = actual(build)
    initial  = resolved.first(4).map { |a| a["pubkey"] }

    extras = resolved[4..].map { |a| a["pubkey"] }
    expect(extras).not_to be_empty
    expect(extras & initial).to be_empty
  end

  it "reads the hook program id off the mint" do
    expect(transfer.hook_program_for(FIXTURE["mint"])).to eq(FIXTURE["hook_program_id"])
  end

  it "reads the decimals off the mint" do
    expect(transfer.mint_info(FIXTURE["mint"]).decimals).to eq(FIXTURE["decimals"])
  end

  # A mint with no hook still has to transfer. Callers should be able to route
  # every SPL transfer through this without knowing which mints are restricted.
  context "a mint with no transfer hook" do
    let(:plain_mint) { "So11111111111111111111111111111111111111112" }
    let(:accounts) do
      base = "\x00".b * 82
      super().merge(plain_mint => base)
    end

    it "has no hook program" do
      expect(transfer.hook_program_for(plain_mint)).to be_nil
    end

    it "builds a plain four-account transfer" do
      ix = transfer.transfer_checked(
        mint:        plain_mint,
        source:      FIXTURE["source"],
        destination: FIXTURE["destination"],
        authority:   FIXTURE["authority"],
        amount:      1
      )
      expect(ix.accounts.length).to eq(4)
    end
  end

  # A mint can point at a hook whose ExtraAccountMetaList has not been created
  # — between `initialize_offering_config` and `initialize_extra_account_meta_list`
  # that is exactly the state. Transfers cannot work then, and the client should
  # say why rather than build a list that Token-2022 rejects for its own reasons.
  context "a hook whose validation account does not exist" do
    let(:accounts) do
      validation = FIXTURE["accounts"].last["pubkey"]
      super().reject { |pubkey, _| pubkey == validation }
    end

    it "raises naming the missing account" do
      expect { build }.to raise_error(
        IoniqxRwa::ExtraAccountMetas::ResolutionError, /account not found/
      )
    end
  end

  # An extension-carrying mint whose hook program id is cleared is unrestricted
  # again, and must not be treated as if it still had one.
  context "a mint carrying the extension with the hook cleared" do
    let(:cleared_mint) { "So11111111111111111111111111111111111111112" }
    let(:accounts) do
      data = +("\x00".b * 165)
      data << [ 1 ].pack("C")                       # AccountType::Mint
      data << [ 14, 64 ].pack("vv")                 # TransferHook, 64 bytes
      data << ("\x00".b * 64)                       # authority + program id, both None
      super().merge(cleared_mint => data)
    end

    it "has no hook program" do
      expect(transfer.hook_program_for(cleared_mint)).to be_nil
    end
  end
end
