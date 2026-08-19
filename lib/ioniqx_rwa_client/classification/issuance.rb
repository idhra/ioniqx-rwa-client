# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "solana/ruby/kit"

module IoniqxRwa
  module Classification
    # Write-side counterpart to the reader in classification.rb: encodes a
    # `rwa.classification.v1` payload and builds the Solana Attestation Service
    # `createAttestation` instruction that carries it (BUILD.md §2.6, draft §3).
    #
    # Same scope boundary as the reader. This publishes a *description* of what
    # a token represents. It is not a compliance action, it gates nothing, and
    # no ioniqx Anchor program reads what it writes.
    #
    # Layer 1 (the `rwa.*` additionalMetadata keys) is written by the mint
    # creation path, not here - see SplTokenService#create_mint in ioniqx-app,
    # which already emits them through the Token-2022 metadata interface.
    module Issuance
      Addresses    = Solana::Ruby::Kit::Addresses
      Codecs       = Solana::Ruby::Kit::Codecs
      Instructions = Solana::Ruby::Kit::Instructions

      U32_LE = Codecs.u32_codec(endian: :little)
      I64_LE = Codecs.i64_codec(endian: :little)

      SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"

      # SAS instruction discriminator, a plain u8 - not an Anchor 8-byte hash.
      # Pinned to sas-lib@1.0.10.
      CREATE_ATTESTATION_DISCRIMINATOR = 6

      class EncodeError < IoniqxRwa::Error
        def self.error_code = :IONIQX__CLASSIFICATION_ENCODE_FAILED
      end

      class << self
        # Encode a `rwa.classification.v1` Borsh payload (draft §3.1).
        #
        # Nine positional fields in normative order. Accepts the same shapes
        # {Classification.decode_payload} returns, so encode(decode(x)) == x.
        #
        # `mint` and `discovery_signer` are base58 addresses here and go on the
        # wire as 32 raw bytes; `property_commit` is already raw bytes.
        #
        # Optional string fields are written as empty strings rather than
        # omitted - Borsh is positional, so there is no such thing as an absent
        # field. `property_commit` and `discovery_signer` are the two that can
        # be genuinely empty (a zero-length Vec<u8>), which is how the draft
        # says to express "none" rather than 32 zero bytes.
        def encode_payload(mint:, asset_class:, claim:, subclass: nil, jurisdiction: nil,
                           issuer_lei: nil, property_commit: nil, discovery_url: nil,
                           discovery_signer: nil)
          validate_vocabulary!(asset_class, claim)

          commit = property_commit.to_s.b
          unless commit.empty? || commit.bytesize == 32
            raise EncodeError, "property_commit is #{commit.bytesize} bytes, expected 32 or empty"
          end

          vec(key_bytes(mint)) +
            str(asset_class) + str(claim) + str(subclass) +
            str(jurisdiction) + str(issuer_lei) +
            vec(commit) +
            str(discovery_url) +
            vec(discovery_signer.nil? ? "".b : key_bytes(discovery_signer))
        end

        # Build the SAS `createAttestation` instruction.
        #
        # Accounts, in the order the program expects (sas-lib@1.0.10):
        #   0 payer          writable, signer
        #   1 authority      readonly, signer  - an authorized signer of the credential
        #   2 credential     readonly
        #   3 schema         readonly
        #   4 attestation    writable          - the PDA being created
        #   5 systemProgram  readonly
        #
        # Data: u8 discriminator | nonce:[u8;32] | data:(u32 len + bytes) | expiry:i64
        #
        # `nonce` is fixed to the subject mint (draft §3.3), which is what makes
        # the attestation derivable from the mint alone. It is passed here as a
        # raw 32-byte address, NOT length-prefixed - unlike the payload's `mint`
        # field, which is a Borsh Vec<u8>. The two look alike and encode
        # differently.
        #
        # @param expires_at [Integer] unix seconds. Mandatory: an attestation
        #   without expiry is a claim about the past presented as a claim about
        #   the present, and revocation deletes the account so it cannot be
        #   relied on as the withdrawal path (draft §3.2, §3.4).
        def create_attestation_instruction(payer:, authority:, credential:, schema:, mint:,
                                           payload:, expires_at:, program_id: Config::SAS_PROGRAM_ID)
          raise EncodeError, "expires_at must be a positive unix timestamp" unless expires_at.to_i.positive?

          attestation = Classification.attestation_pda(
            credential: credential, schema: schema, mint: mint, program_id: program_id
          )

          data = [CREATE_ATTESTATION_DISCRIMINATOR].pack("C") +
                 key_bytes(mint) +
                 vec(payload.b) +
                 I64_LE.encode(expires_at.to_i)

          Instructions::Instruction.new(
            program_address: Addresses.address(program_id.to_s),
            accounts: [
              writable_signer(payer),
              readonly_signer(authority),
              readonly(credential),
              readonly(schema),
              writable(attestation),
              readonly(SYSTEM_PROGRAM_ID)
            ],
            data: data
          )
        end

        # Convenience: encode a payload and build the instruction in one step,
        # returning both the instruction and the address it will create.
        #
        # @return [Hash] :instruction, :attestation, :payload
        def attest(payer:, authority:, credential:, schema:, mint:, expires_at:,
                   program_id: Config::SAS_PROGRAM_ID, **fields)
          payload = encode_payload(mint: mint, **fields)

          {
            instruction: create_attestation_instruction(
              payer: payer, authority: authority, credential: credential, schema: schema,
              mint: mint, payload: payload, expires_at: expires_at, program_id: program_id
            ),
            attestation: Classification.attestation_pda(
              credential: credential, schema: schema, mint: mint, program_id: program_id
            ),
            payload: payload
          }
        end

        private

        def validate_vocabulary!(asset_class, claim)
          unless Classification.rwa_class?(asset_class)
            raise EncodeError, "rwa.class #{asset_class.inspect} is not in the draft §2.1 set"
          end
          # Always required and orthogonal to class: a first-lien note and an
          # equity stake in the same building are both real-estate with
          # inverted risk (draft §2.2).
          unless Classification.rwa_claim?(claim)
            raise EncodeError, "rwa.claim #{claim.inspect} is not in the draft §2.2 set"
          end
        end

        # Borsh Vec<u8> and String share a wire shape: u32 LE length + bytes.
        def vec(bytes) = U32_LE.encode(bytes.bytesize) + bytes.b
        def str(value) = vec(value.to_s.b)

        def key_bytes(key) = Addresses.decode_address(Addresses.address(key.to_s))

        def readonly(address)        = Instructions.readonly_account(Addresses.address(address.to_s))
        def writable(address)        = Instructions.writable_account(Addresses.address(address.to_s))
        def readonly_signer(address) = Instructions.readonly_signer_account(Addresses.address(address.to_s))
        def writable_signer(address) = Instructions.writable_signer_account(Addresses.address(address.to_s))
      end
    end
  end
end
