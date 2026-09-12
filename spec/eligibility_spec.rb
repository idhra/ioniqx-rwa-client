# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"
require "json"
require "base64"
require "ioniqx_rwa_client/eligibility"

# The roster gate, client side.
#
# Token-2022 builds the hook's CPI itself and its data is the transfer amount
# and nothing else, so a proof cannot ride on the transfer. It travels as its
# own prepended instruction and the hook introspects for it — which makes the
# discriminator and the argument encoding a cross-language contract, not an
# internal detail.
RSpec.describe IoniqxRwa::Eligibility do
  let(:hook) { "2TYjyHt3XKoHJ7q217YLGiz1sCHYiLD64sioJqfQuWPK" }
  let(:holder) { "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" }

  describe ".prove" do
    # The hook scans the transaction comparing these eight bytes. A mismatch is
    # silent and total: every gated transfer fails for want of a proof that was
    # in the transaction all along.
    it "carries Anchor's sighash for the program's handler" do
      expect(described_class::PROVE_ELIGIBILITY)
        .to eq(Digest::SHA256.digest("global:prove_eligibility")[0, 8])
    end

    it "encodes the holder and the siblings the way the program decodes them" do
      siblings = [ "ab" * 32, "cd" * 32 ]
      ix = described_class.prove(hook_program_id: hook, holder: holder, proof: siblings)

      expect(ix.program_address.to_s).to eq(hook)
      expect(ix.data.byteslice(0, 8)).to eq(described_class::PROVE_ELIGIBILITY)
      expect(ix.data.byteslice(8, 32))
        .to eq(Solana::Ruby::Kit::Addresses.decode_address(
                 Solana::Ruby::Kit::Addresses.address(holder)
               ))
      expect(ix.data.byteslice(40, 4).unpack1("V")).to eq(2)
      expect(ix.data.byteslice(44, 32)).to eq("\xAB".b * 32)
      expect(ix.data.byteslice(76, 32)).to eq("\xCD".b * 32)
      expect(ix.data.bytesize).to eq(108)
    end

    # The carrier exists to put bytes where the hook can read them. Reading a
    # proof needs nothing else.
    it "takes no accounts" do
      ix = described_class.prove(hook_program_id: hook, holder: holder, proof: [])
      expect(ix.accounts).to be_empty
    end

    # A one-holder roster makes the leaf the root. A client treating [] as "no
    # proof" would refuse a transfer that is perfectly good.
    it "treats an empty proof as a proof, not as its absence" do
      ix = described_class.prove(hook_program_id: hook, holder: holder, proof: [])

      expect(ix.data.byteslice(40, 4).unpack1("V")).to eq(0)
      expect(ix.data.bytesize).to eq(44)
    end

    # A 32-character hex string is also 32 raw bytes, so sniffing between the
    # two takes a caller who meant 16 bytes and builds a proof that cannot
    # verify — and the failure surfaces as a rejected transfer, far from here.
    it "refuses a sibling that is not 64-character hex" do
      expect { described_class.prove(hook_program_id: hook, holder: holder, proof: [ "ab" * 16 ]) }
        .to raise_error(IoniqxRwa::Eligibility::ProofError, /64-character hex/)
      expect { described_class.prove(hook_program_id: hook, holder: holder, proof: [ "\xAB".b * 32 ]) }
        .to raise_error(IoniqxRwa::Eligibility::ProofError, /64-character hex/)
    end

    # The program refuses anything deeper before walking it; failing here means
    # the caller can still read why.
    it "refuses a proof deeper than the program will verify" do
      deep = Array.new(described_class::MAX_PROOF_DEPTH + 1) { "00" * 32 }

      expect { described_class.prove(hook_program_id: hook, holder: holder, proof: deep) }
        .to raise_error(IoniqxRwa::Eligibility::ProofError, /refuses more than/)
    end
  end

  # Hand-computed offsets are exactly the thing that is wrong by one and looks
  # right. These read the account bytes the *program* emitted into the fixture,
  # from a LiteSVM run that did a real transfer — so the assertion is that Ruby
  # reads the config the way Rust wrote it.
  describe ".gate_from_config" do
    # `let`, not constants: a constant assigned inside a describe block lands
    # on Object, and another spec in this suite already owns FIXTURE_PATH.
    let(:fixture_path) { File.expand_path("fixtures/client_resolution.json", __dir__) }
    let(:config_len) { IoniqxRwa::Eligibility::Offsets::ACCOUNT_LEN }

    let(:config_bytes) do
      data = JSON.parse(File.read(fixture_path))["account_data"]
      found = data.values.map { |b64| Base64.decode64(b64) }
                  .find { |bytes| bytes.bytesize == config_len }
      raise "no #{config_len}-byte offering config in the fixture" if found.nil?

      found
    end

    it "reads an unpublished gate off an offering that has never had a roster" do
      gate = described_class.gate_from_config(config_bytes)

      expect(gate.enforced).to be(false)
      expect(gate.proof_required?).to be(false)
      expect(gate.merkle_root).to eq("\x00".b * 32)
      expect(gate.root_updated_at).to eq(0)
    end

    # The structure branch sits immediately before the gate, so decoding it
    # correctly is what proves the gate's own offset is not one field adrift.
    it "finds the structure model exactly where the gate offset implies" do
      expect(config_bytes.getbyte(described_class::Offsets::STRUCTURE_MODEL)).to eq(1)
    end

    it "refuses a truncated account rather than reading past it" do
      expect { described_class.gate_from_config(config_bytes.byteslice(0, 100)) }
        .to raise_error(IoniqxRwa::Eligibility::ProofError, /expected at least/)
    end
  end

  describe "Gate#stale?" do
    # The bound cuts both ways: it stops a stale roster authorising a lapsed
    # holder, and once crossed it refuses every legitimate transfer too.
    it "is stale once the bound has passed" do
      gate = described_class::Gate.new(merkle_root: "\x01".b * 32, root_updated_at: 1_000,
                                       max_staleness_secs: 60, enforced: true)

      expect(gate.stale?(1_050)).to be(false)
      expect(gate.stale?(1_100)).to be(true)
    end

    it "is never stale when the gate is not enforced" do
      gate = described_class::Gate.new(merkle_root: "\x00".b * 32, root_updated_at: 0,
                                       max_staleness_secs: 0, enforced: false)

      expect(gate.stale?(Time.now.to_i)).to be(false)
    end
  end
end
