# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"
require "digest"
require "json"
require "base64"
require "ioniqx_rwa_client/extra_account_metas"

# Golden-vector spec for IoniqxRwa::ExtraAccountMetas.
#
# The resolver is the one piece of the gem with no solana-ruby-kit coverage and
# real byte-level logic, so it is proven two ways:
#
#   1. Pure-unit vectors (no network): a hand-built validation-account byte
#      buffer with known ExtraAccountMeta records — static pubkey, PDA off the
#      hook program (Literal + AccountKey seeds), and a PDA off another listed
#      program. Asserts the resolver reproduces addresses, order, and
#      signer/writable flags exactly. These run in CI with zero dependencies.
#
#   2. Reference cross-check (opt-in, network): against a real devnet mint whose
#      ExtraAccountMetaList was initialized by the deployed hook program, assert
#      the resolved list is byte-identical to what @solana/kit + spl-transfer-hook
#      produce in TypeScript. The expected list is committed as a fixture emitted
#      by the TS reference resolver, so this test needs no live TS runtime — only
#      an RPC endpoint to fetch the validation account. Gated behind
#      IONIQX_GOLDEN_DEVNET=1 so the offline suite stays hermetic.
#
# To regenerate the devnet fixture, run the TS reference resolver
# (scripts/emit_golden_vectors.ts in the Rust workspace) against the same mint
# and commit its JSON output to spec/fixtures/.

RSpec.describe IoniqxRwa::ExtraAccountMetas do
  # ---- helpers to build a validation-account byte buffer by hand -----------

  # A single 35-byte ExtraAccountMeta record.
  def extra_meta(discriminator:, address_config:, signer:, writable:)
    raise "address_config must be 32 bytes" unless address_config.bytesize == 32

    [discriminator].pack("C") +
      address_config +
      [signer ? 1 : 0].pack("C") +
      [writable ? 1 : 0].pack("C")
  end

  # Pack a Seed::Literal entry: variant(1) | len(1) | bytes.
  def seed_literal(bytes)
    [IoniqxRwa::ExtraAccountMetas::SEED_LITERAL, bytes.bytesize].pack("CC") + bytes
  end

  # Pack a Seed::AccountKey entry: variant(3) | index(1).
  def seed_account_key(index)
    [IoniqxRwa::ExtraAccountMetas::SEED_ACCOUNT_KEY, index].pack("CC")
  end

  # Pack a Seed::InstructionData entry: variant(2) | index(1) | length(1).
  def seed_instruction_data(index:, length:)
    [IoniqxRwa::ExtraAccountMetas::SEED_INSTRUCTION_DATA, index, length].pack("CCC")
  end

  # Right-pad a packed-seed sequence into the fixed 32-byte address_config,
  # zero-terminated (0 == Seed::Uninitialized).
  def address_config(*packed_seeds)
    joined = packed_seeds.join
    raise "seeds exceed 32 bytes" if joined.bytesize > 32

    joined + ("\x00" * (32 - joined.bytesize))
  end

  # Wrap a list of 35-byte records into a full validation-account buffer:
  #   [8] Execute discriminator | [4] u32 LE TLV length | [4] u32 LE count | records
  def validation_buffer(records)
    count      = records.length
    pod_slice  = Codecs.u32_codec(endian: :little).encode(count) + records.join
    tlv_length = pod_slice.bytesize
    IoniqxRwa::ExtraAccountMetas::EXECUTE_DISCRIMINATOR +
      Codecs.u32_codec(endian: :little).encode(tlv_length) +
      pod_slice
  end

  # Deterministic 32-byte pubkeys for fixtures.
  def b58(seed_byte)
    Addresses.encode_address((seed_byte.chr * 32))
  end

  let(:hook_program_id) { b58(0x11) }
  let(:mint)            { b58(0x22) }
  let(:source)          { b58(0x33) }
  let(:destination)     { b58(0x44) }
  let(:authority)       { b58(0x55) }
  let(:static_extra)    { b58(0x66) }
  let(:other_program)   { b58(0x77) }
  let(:amount)          { 1_000_000 }

  # Compute the validation PDA the resolver will look for, and seed the FakeRpc
  # store at that address with our hand-built buffer.
  def validation_address_for(records, rpc_store)
    subject = described_class.new(SpecSupport::FakeRpc.new({}))
    v = subject.validation_pda(mint: mint, hook_program_id: hook_program_id)
    rpc_store[v] = validation_buffer(records)
    v
  end

  # ---- BUILD.md §5.3 pre-flight constants ---------------------------------
  #
  # These pin the two constants §5.3 says to verify before trusting the
  # resolver against a real transfer. Both are derived here from their
  # authoritative source rather than restated, so a drift in either the SPL
  # interface or the kit fails the offline suite instead of a live transfer.
  describe "pinned constants (BUILD.md §5.3)" do
    it "EXECUTE_DISCRIMINATOR is the SplDiscriminate of the interface namespace" do
      # spl_transfer_hook_interface::instruction::ExecuteInstruction derives
      # SplDiscriminate from the literal namespace string; SplDiscriminate is
      # sha256(namespace)[0, 8].
      expected = Digest::SHA256.digest("spl-transfer-hook-interface:execute").byteslice(0, 8)

      expect(described_class::EXECUTE_DISCRIMINATOR).to eq(expected)
      expect(described_class::EXECUTE_DISCRIMINATOR.bytes)
        .to eq([105, 37, 101, 197, 75, 251, 102, 26])
    end

    it "TOKEN_2022_PROGRAM_ID matches the kit's own constant" do
      kit_id = Solana::Ruby::Kit::Programs::AssociatedTokenAccount::TOKEN_2022_PROGRAM_ID

      expect(described_class::TOKEN_2022_PROGRAM_ID).to eq(kit_id.to_s)
    end

    it "an ExtraAccountMeta record is 35 bytes: u8 + [u8;32] + u8 + u8" do
      expect(described_class::EXTRA_META_SIZE).to eq(1 + 32 + 1 + 1)
    end
  end

  describe "#validation_pda" do
    it "derives ['extra-account-metas', mint] off the hook program" do
      subject = described_class.new(SpecSupport::FakeRpc.new({}))
      expected = Addresses.get_program_derived_address(
        program_address: Addresses.address(hook_program_id),
        seeds: ["extra-account-metas", Addresses.decode_address(Addresses.address(mint))]
      ).address.to_s

      expect(subject.validation_pda(mint: mint, hook_program_id: hook_program_id))
        .to eq(expected)
    end
  end

  describe "#resolve" do
    context "a single static-address extra account (discriminator 0)" do
      it "returns the static pubkey with its flags, then hook program + validation" do
        store = {}
        records = [
          extra_meta(
            discriminator: 0,
            address_config: Addresses.decode_address(Addresses.address(static_extra)),
            signer: false,
            writable: true
          )
        ]
        validation = validation_address_for(records, store)
        subject = described_class.new(SpecSupport::FakeRpc.new(store))

        result = subject.resolve(
          mint: mint, source: source, destination: destination,
          authority: authority, amount: amount, hook_program_id: hook_program_id
        )

        expect(result.length).to eq(3) # 1 extra + hook program + validation
        expect(result[0]).to eq(pubkey: static_extra, writable: true, signer: false)
        expect(result[1]).to eq(pubkey: hook_program_id, writable: false, signer: false)
        expect(result[2]).to eq(pubkey: validation, writable: false, signer: false)
      end
    end

    context "a PDA off the hook program (discriminator 1) using Literal + AccountKey seeds" do
      it "derives the PDA from the resolved running-account list" do
        store = {}
        # seeds: literal "holder" + AccountKey{index: 3} (the authority, in the
        # running list: 0 source, 1 mint, 2 destination, 3 authority, 4 validation)
        cfg = address_config(seed_literal("holder"), seed_account_key(3))
        records = [
          extra_meta(discriminator: 1, address_config: cfg, signer: false, writable: false)
        ]
        validation_address_for(records, store)
        subject = described_class.new(SpecSupport::FakeRpc.new(store))

        result = subject.resolve(
          mint: mint, source: source, destination: destination,
          authority: authority, amount: amount, hook_program_id: hook_program_id
        )

        expected_pda = Addresses.get_program_derived_address(
          program_address: Addresses.address(hook_program_id),
          seeds: ["holder", Addresses.decode_address(Addresses.address(authority))]
        ).address.to_s

        expect(result.first).to eq(pubkey: expected_pda, writable: false, signer: false)
      end
    end

    context "InstructionData seed slices the Execute data (disc + u64 amount)" do
      it "uses the amount bytes as a seed" do
        store = {}
        # Execute data = 8-byte disc + u64 LE amount; slice the 8 amount bytes at offset 8.
        cfg = address_config(seed_instruction_data(index: 8, length: 8))
        records = [
          extra_meta(discriminator: 1, address_config: cfg, signer: false, writable: false)
        ]
        validation_address_for(records, store)
        subject = described_class.new(SpecSupport::FakeRpc.new(store))

        result = subject.resolve(
          mint: mint, source: source, destination: destination,
          authority: authority, amount: amount, hook_program_id: hook_program_id
        )

        expected_pda = Addresses.get_program_derived_address(
          program_address: Addresses.address(hook_program_id),
          seeds: [Codecs.u64_codec(endian: :little).encode(amount)]
        ).address.to_s

        expect(result.first[:pubkey]).to eq(expected_pda)
      end
    end

    context "a PDA off another listed program (discriminator 128 + i)" do
      it "derives off the program at the referenced running-list index" do
        store = {}
        # First extra (index 5) is the external program as a static address.
        # Second extra (index 6) is a PDA off that program: discriminator 128+5.
        prog_meta = extra_meta(
          discriminator: 0,
          address_config: Addresses.decode_address(Addresses.address(other_program)),
          signer: false, writable: false
        )
        cfg = address_config(seed_literal("vault"))
        pda_meta = extra_meta(discriminator: 128 + 5, address_config: cfg,
                              signer: false, writable: true)
        records = [prog_meta, pda_meta]
        validation_address_for(records, store)
        subject = described_class.new(SpecSupport::FakeRpc.new(store))

        result = subject.resolve(
          mint: mint, source: source, destination: destination,
          authority: authority, amount: amount, hook_program_id: hook_program_id
        )

        expected_pda = Addresses.get_program_derived_address(
          program_address: Addresses.address(other_program),
          seeds: ["vault"]
        ).address.to_s

        # result[0] = external program (static), result[1] = the derived PDA
        expect(result[0][:pubkey]).to eq(other_program)
        expect(result[1]).to eq(pubkey: expected_pda, writable: true, signer: false)
      end
    end

    context "ordering: a later meta references an earlier resolved extra by index" do
      it "resolves in order so index references are already populated" do
        store = {}
        # index 5: static program; index 6: PDA off hook program seeded by
        # AccountKey{index: 5} (the just-resolved static extra).
        static_meta = extra_meta(
          discriminator: 0,
          address_config: Addresses.decode_address(Addresses.address(static_extra)),
          signer: false, writable: false
        )
        cfg = address_config(seed_account_key(5))
        dependent = extra_meta(discriminator: 1, address_config: cfg,
                               signer: false, writable: false)
        records = [static_meta, dependent]
        validation_address_for(records, store)
        subject = described_class.new(SpecSupport::FakeRpc.new(store))

        result = subject.resolve(
          mint: mint, source: source, destination: destination,
          authority: authority, amount: amount, hook_program_id: hook_program_id
        )

        expected_pda = Addresses.get_program_derived_address(
          program_address: Addresses.address(hook_program_id),
          seeds: [Addresses.decode_address(Addresses.address(static_extra))]
        ).address.to_s

        expect(result[1][:pubkey]).to eq(expected_pda)
      end
    end

    context "malformed validation data" do
      it "raises when the Execute TLV entry is absent" do
        store = {}
        subject_for_pda = described_class.new(SpecSupport::FakeRpc.new({}))
        v = subject_for_pda.validation_pda(mint: mint, hook_program_id: hook_program_id)
        store[v] = "\x00" * 32 # no Execute discriminator
        subject = described_class.new(SpecSupport::FakeRpc.new(store))

        expect {
          subject.resolve(
            mint: mint, source: source, destination: destination,
            authority: authority, amount: amount, hook_program_id: hook_program_id
          )
        }.to raise_error(IoniqxRwa::ExtraAccountMetas::ResolutionError)
      end

      it "raises when the PodSlice is truncated" do
        store = {}
        subject_for_pda = described_class.new(SpecSupport::FakeRpc.new({}))
        v = subject_for_pda.validation_pda(mint: mint, hook_program_id: hook_program_id)
        # Claim 2 records but supply zero bytes of record data.
        truncated = IoniqxRwa::ExtraAccountMetas::EXECUTE_DISCRIMINATOR +
                    Codecs.u32_codec(endian: :little).encode(4) +
                    Codecs.u32_codec(endian: :little).encode(2)
        store[v] = truncated
        subject = described_class.new(SpecSupport::FakeRpc.new(store))

        expect {
          subject.resolve(
            mint: mint, source: source, destination: destination,
            authority: authority, amount: amount, hook_program_id: hook_program_id
          )
        }.to raise_error(IoniqxRwa::ExtraAccountMetas::ResolutionError, /truncated/)
      end
    end
  end

  # ---- Reference cross-check against committed TS-emitted fixture ----------
  #
  # Byte-for-byte parity with @solana/kit + spl-transfer-hook. Runs only when a
  # devnet RPC + fixture are available, so the offline suite stays hermetic.
  describe "reference parity (devnet)", if: ENV["IONIQX_GOLDEN_DEVNET"] == "1" do
    let(:fixture) do
      JSON.parse(File.read("spec/fixtures/golden_devnet_transfer_hook.json"))
    end

    let(:rpc) do
      Solana::Ruby::Kit::Rpc::Client.new(
        Solana::Ruby::Kit::RpcTypes.devnet(ENV.fetch("SOLANA_RPC_URL", nil) || "https://api.devnet.solana.com")
      )
    end

    it "matches the TypeScript reference resolver exactly" do
      subject = described_class.new(rpc)

      result = subject.resolve(
        mint:            fixture["mint"],
        source:          fixture["source"],
        destination:     fixture["destination"],
        authority:       fixture["authority"],
        amount:          fixture["amount"],
        hook_program_id: fixture["hook_program_id"]
      )

      # fixture["expected"] is an ordered list of { pubkey, signer, writable }
      # as emitted by the TS reference resolver.
      normalized = result.map { |m| { "pubkey" => m[:pubkey], "signer" => m[:signer], "writable" => m[:writable] } }

      expect(normalized).to eq(fixture["expected"])
    end
  end
end
