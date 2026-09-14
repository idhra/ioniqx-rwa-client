# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "digest"
require "solana/ruby/kit"

module IoniqxRwa
  # The roster gate: proving a holder is in an offering's eligible set.
  #
  # An offering may gate transfers on a merkle root as well as on each holder's
  # attestation. The root is published on chain; the set behind it is not, which
  # is the privacy property the gate exists for and the reason nothing on chain
  # can generate a proof. The client fetches one and supplies it.
  #
  # ## Why this cannot ride on the transfer
  #
  # Token-2022 builds the hook's `Execute` CPI itself, and its instruction data
  # is the transfer amount and nothing else. There is no way to hand the hook a
  # proof through the transfer. So the proof travels as its own top-level
  # instruction, *prepended*, and the hook introspects the transaction for it.
  #
  # Prepended, not appended: the hook scans only instructions before the one
  # executing. A proof after the transfer has not been seen by the runtime when
  # the hook runs.
  #
  # ## Where a proof comes from
  #
  # From whoever published the root. For ioniqx-issued tokens that is
  # `GET /eligibility/:mint/:wallet` on the issuing platform, which returns the
  # proof as hex strings along with the root it was built against. This gem
  # takes the proof as an argument rather than fetching it: the program is the
  # thing this library knows about, and a deployment that publishes its own
  # roots should not have an ioniqx URL compiled into its client.
  #
  # ## A proof is not a credential
  #
  # It is public data, and supplying one proves nothing on its own. The hook
  # computes the leaf itself from its own mint and its own view of the token
  # account owner; only the sibling hashes come from here. That is why a proof
  # can be fetched over plain HTTP, cached, and handed around without care.
  module Eligibility
    Addresses    = Solana::Ruby::Kit::Addresses
    Codecs       = Solana::Ruby::Kit::Codecs
    Instructions = Solana::Ruby::Kit::Instructions

    # `sha256("global:prove_eligibility")[0, 8]` — Anchor's sighash.
    PROVE_ELIGIBILITY = Digest::SHA256.digest("global:prove_eligibility")[0, 8].freeze

    # Matches `merkle::MAX_PROOF_DEPTH` in the program, which refuses anything
    # longer before walking it. Checked here so an overlong proof fails while
    # the caller can still read the reason.
    MAX_PROOF_DEPTH = 24

    OFFERING_CONFIG_SEED = "offering-config"

    U32_LE = Codecs.u32_codec(endian: :little)
    U64_LE = Codecs.u64_codec(endian: :little)

    # Byte offsets into the `OfferingConfig` account, Anchor's 8-byte
    # discriminator included.
    #
    # Hand-computed offsets are exactly the kind of thing that is wrong by one
    # and looks right, so these are pinned by `eligibility_spec.rb` against the
    # account bytes the program itself emitted into
    # `spec/fixtures/client_resolution.json`.
    module Offsets
      MERKLE_ROOT        = 262
      ROOT_UPDATED_AT    = 294
      MAX_STALENESS_SECS = 302
      ROOT_ENFORCED      = 306
      STRUCTURE_MODEL    = 235
      # The wallet a redemption leg must move tokens to. Appended after the
      # gate, so every offset above is unchanged by it.
      REDEMPTION_TREASURY = 307
      ACCOUNT_LEN        = 339
    end

    # What an offering's config says about its roster gate.
    Gate = Struct.new(:merkle_root, :root_updated_at, :max_staleness_secs, :enforced,
                      keyword_init: true) do
      # Whether a transfer of this mint needs a proof attached.
      def proof_required? = enforced

      # Whether the hook will refuse the root as too old.
      #
      # The bound cuts both ways: it stops a roster nobody has refreshed from
      # authorising a holder who lapsed, and once crossed it refuses every
      # legitimate transfer too. A caller seeing this should wait for the
      # issuer's next publication rather than retry immediately — nothing they
      # can do makes the root younger.
      def stale?(at = Time.now.to_i)
        enforced && (at - root_updated_at) > max_staleness_secs
      end

      def root_hex = merkle_root.unpack1("H*")
    end

    class ProofError < IoniqxRwa::Error
      def self.error_code = :IONIQX__ELIGIBILITY_PROOF_INVALID
    end

    module_function

    # The instruction to prepend.
    #
    # @param hook_program_id [String] the mint's transfer hook program
    # @param holder [String] the wallet being proved. The hook matches on this,
    #   so a transfer needing proofs for both sides carries two instructions.
    # @param proof [Array<String>] sibling hashes as 64-character hex, which is
    #   what the publishing endpoint returns. Raw bytes are deliberately not
    #   accepted: a 32-character hex string is also 32 raw bytes, so sniffing
    #   between the two silently takes a caller who meant 16 bytes and builds a
    #   proof that cannot verify. Callers holding bytes pass `.unpack1("H*")`.
    #
    #   An **empty array is a valid proof** — it is what a one-holder roster
    #   produces, where the leaf is the root. Treating it as "no proof" would
    #   refuse a transfer that is perfectly good.
    def prove(hook_program_id:, holder:, proof:)
      siblings = Array(proof).map { |s| normalize_sibling(s) }

      if siblings.length > MAX_PROOF_DEPTH
        raise ProofError, "proof is #{siblings.length} levels; the program refuses more than #{MAX_PROOF_DEPTH}"
      end

      data = PROVE_ELIGIBILITY +
             Addresses.decode_address(Addresses.address(holder)) +
             U32_LE.encode(siblings.length) +
             siblings.join

      Instructions::Instruction.new(
        program_address: Addresses.address(hook_program_id),
        # The carrier takes no accounts. It exists to put bytes in the
        # transaction where the hook can introspect them, and reading a proof
        # needs nothing but the proof.
        accounts:        [],
        data:            data
      )
    end

    # Decodes the roster gate out of an offering config account's bytes.
    def gate_from_config(data)
      unless data.is_a?(String) && data.bytesize >= Offsets::ACCOUNT_LEN
        raise ProofError, "offering config is #{data.to_s.bytesize} bytes, expected at least #{Offsets::ACCOUNT_LEN}"
      end

      Gate.new(
        merkle_root:        data.byteslice(Offsets::MERKLE_ROOT, 32),
        # The kit's decoders return [value, bytes_consumed].
        root_updated_at:    U64_LE.decode(data.byteslice(Offsets::ROOT_UPDATED_AT, 8)).first,
        max_staleness_secs: U32_LE.decode(data.byteslice(Offsets::MAX_STALENESS_SECS, 4)).first,
        enforced:           data.getbyte(Offsets::ROOT_ENFORCED) == 1
      )
    end

    # The offering config PDA for a mint.
    def config_address(mint:, hook_program_id:)
      Addresses.get_program_derived_address(
        program_address: Addresses.address(hook_program_id),
        seeds:           [ OFFERING_CONFIG_SEED.b, Addresses.decode_address(Addresses.address(mint)) ]
      ).address.to_s
    end

    def normalize_sibling(value)
      hex = value.to_s
      unless hex.match?(/\A\h{64}\z/)
        raise ProofError,
              "proof entries must be 64-character hex, got #{hex.length} characters. " \
              "Raw bytes are not sniffed for: 32 hex characters are also 32 bytes, and " \
              "guessing between them builds a proof that cannot verify."
      end

      [ hex ].pack("H*")
    end
  end
end
