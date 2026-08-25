# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "base64"

require "solana/ruby/kit"

require_relative "errors"

module IoniqxRwa
  # Resolves the extra accounts a Token-2022 *transfer hook* requires, so a
  # transfer instruction carries every account the hook's `Execute` needs.
  #
  # Why this file exists: the anza kit (solana-ruby-kit) builds transactions,
  # derives PDAs, and encodes/decodes bytes, but has no notion of a transfer
  # hook's ExtraAccountMetaList. That resolution is the one piece with no kit
  # support and non-trivial logic, so it lives here.
  #
  # What it implements (authoritative sources):
  #   - Validation account PDA: seeds ["extra-account-metas", mint] off the hook program.
  #   - TLV layout: 8-byte `Execute` discriminator, u32 LE length, then a PodSlice
  #     of fixed 35-byte `ExtraAccountMeta` records.
  #   - ExtraAccountMeta record: discriminator:u8 | address_config:[u8;32] |
  #     is_signer:u8 | is_writable:u8  (== 35 bytes).
  #   - Meta discriminator: 0 = static pubkey; 1 = PDA off the hook program;
  #     (128 + i) = PDA off the program at index i in the running account list.
  #   - Seed enum packed into the 32-byte address_config, variants:
  #       1 Literal | 2 InstructionData | 3 AccountKey | 4 AccountData
  #     (variant 0 = Uninitialized / terminator).
  #
  # Resolution follows the interface's offchain helper: the running account list
  # seeds with the five `Execute` accounts (source, mint, destination, authority,
  # validation) in order, and each resolved meta is appended so that later entries
  # can reference earlier ones by index. Order is therefore load-bearing — a meta
  # that seeds off AccountKey{index: 6} needs entry 6 already resolved.
  #
  # This resolver handles the offchain case: static addresses, PDAs off the hook
  # program, PDAs off another already-listed program, and the four seed variants.
  # It does NOT chase AccountData seeds whose source account is itself one of the
  # not-yet-fetched extra accounts (rare, and flagged with a clear raise) — that
  # would require recursive fetching mid-resolution.
  class ExtraAccountMetas
    Addresses = Solana::Ruby::Kit::Addresses
    Codecs    = Solana::Ruby::Kit::Codecs

    # Token-2022 program id (matches kit's ATA::TOKEN_2022_PROGRAM_ID constant).
    TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

    VALIDATION_SEED = "extra-account-metas"

    # 8-byte SplDiscriminate for the transfer-hook interface `Execute` instruction.
    # Constant per the interface (spl_transfer_hook_interface::instruction::ExecuteInstruction).
    EXECUTE_DISCRIMINATOR = [105, 37, 101, 197, 75, 251, 102, 26].pack("C*").freeze

    EXTRA_META_SIZE = 35 # 1 + 32 + 1 + 1

    # Seed enum variant discriminators (first byte of each packed seed).
    SEED_UNINITIALIZED     = 0
    SEED_LITERAL           = 1
    SEED_INSTRUCTION_DATA  = 2
    SEED_ACCOUNT_KEY       = 3
    SEED_ACCOUNT_DATA      = 4

    ADDRESS_CONFIG_LEN = 32

    # The kit names its number codecs `<type>_codec(endian:)`; there are no
    # `u32_le`/`u64_le` shorthands. Built once - codecs are stateless.
    U32_LE = Codecs.u32_codec(endian: :little)
    U64_LE = Codecs.u64_codec(endian: :little)

    # The gem hard-requires the kit, so this inherits the shared base
    # unconditionally (see errors.rb for why the message shim is needed).
    class ResolutionError < IoniqxRwa::Error
      def self.error_code = :IONIQX__TRANSFER_HOOK_RESOLUTION_FAILED
    end

    # @param rpc [Solana::Ruby::Kit::Rpc::Client] used to fetch validation +
    #   (when AccountData seeds are present) referenced account data.
    def initialize(rpc)
      @rpc = rpc
    end

    # Derive the validation account (ExtraAccountMetaList PDA) for a mint.
    #
    # @param mint [String] base58 mint address
    # @param hook_program_id [String] base58 transfer-hook program id
    # @return [String] base58 validation account address
    def validation_pda(mint:, hook_program_id:)
      pda = Addresses.get_program_derived_address(
        program_address: Addresses.address(hook_program_id),
        seeds: [VALIDATION_SEED, Addresses.decode_address(Addresses.address(mint))]
      )
      pda.address.to_s
    end

    # Resolve every extra AccountMeta for a transfer of `mint`.
    #
    # The five returned-account convention from the interface: callers append
    # these metas to their transfer instruction AFTER the standard transfer
    # accounts, then append the hook program id and the validation account.
    # This method returns ONLY the resolved extras (the `[5..]` slice) plus the
    # trailing [hook_program, validation_account]; it does not re-emit the five
    # Execute accounts, since your transfer instruction already carries them.
    #
    # @param mint [String]
    # @param source [String]        source token account
    # @param destination [String]   destination token account
    # @param authority [String]     transfer authority (owner/delegate)
    # @param amount [Integer]       transfer amount (only needed if a seed slices
    #                               instruction data; safe to pass the real amount)
    # @param hook_program_id [String]
    # @return [Array<AccountMeta>]  extras + [hook_program(ro), validation(ro)]
    def resolve(mint:, source:, destination:, authority:, amount:, hook_program_id:)
      validation = validation_pda(mint: mint, hook_program_id: hook_program_id)
      data = fetch_account_data!(validation)

      metas = parse_validation_tlv(data)

      # Running list seeds with the Execute account order:
      #   0 source, 1 mint, 2 destination, 3 authority, 4 validation
      # (the hook program id is index 5 in the on-chain Execute ix, but for
      #  address_config AccountKey/Program seeds we track the list the resolver
      #  itself builds, matching the offchain helper's account ordering.)
      #
      # All five are recorded READONLY and non-signer. That is not a
      # description of how the transfer instruction carries them - it carries
      # source and destination writable and the authority as a signer. It is
      # the privilege ceiling used for de-escalation below, and the reference
      # resolver (@solana-program/token-2022) pins it at READONLY, so matching
      # it byte-for-byte means matching this too.
      resolved = [
        account_meta(source,      writable: false, signer: false),
        account_meta(mint,        writable: false, signer: false),
        account_meta(destination, writable: false, signer: false),
        account_meta(authority,   writable: false, signer: false),
        account_meta(validation,  writable: false, signer: false)
      ]

      # `Execute` instruction data = 8-byte disc + u64 LE amount, used by any
      # Seed::InstructionData configs.
      ix_data = EXECUTE_DISCRIMINATOR + U64_LE.encode(amount)

      metas.each do |m|
        address = resolve_address(m, resolved, ix_data, hook_program_id)
        meta    = account_meta(address, writable: m[:writable], signer: m[:signer])
        # De-escalate against everything already in the list, so a hook cannot
        # claim signer or writable privileges the transaction has not already
        # granted that address. Without this a malicious or careless validation
        # account could name the fee payer as a writable signer and have the
        # caller sign it unknowingly.
        resolved << de_escalate(meta, resolved)
      end

      extras = resolved[5..] || []
      extras + [
        account_meta(hook_program_id, writable: false, signer: false),
        account_meta(validation,      writable: false, signer: false)
      ]
    end

    private

    # ---- TLV parsing -------------------------------------------------------

    # Validation account data layout:
    #   [8]  Execute discriminator (TLV "Type")
    #   [4]  u32 LE length of the value buffer (TLV "Length")
    #   [4]  u32 LE PodSlice length prefix (entry count)
    #   [N * 35] packed ExtraAccountMeta records
    #
    # We locate the Execute TLV entry, then walk its PodSlice. TLV entries are
    # laid out back-to-back; for the validation account the Execute entry is the
    # only one written by ExtraAccountMetaList::init, so we match on its type.
    def parse_validation_tlv(data)
      raise ResolutionError, "validation account too small" if data.bytesize < 12

      offset = 0
      loop do
        raise ResolutionError, "Execute TLV entry not found" if offset + 12 > data.bytesize

        type   = data.byteslice(offset, 8)
        length = decode_u32_le(data.byteslice(offset + 8, 4))
        value_start = offset + 12

        if type == EXECUTE_DISCRIMINATOR
          value = data.byteslice(value_start, length)
          return parse_pod_slice(value)
        end

        offset = value_start + length
      end
    end

    # PodSlice: u32 LE count, then count * 35-byte records.
    def parse_pod_slice(value)
      raise ResolutionError, "PodSlice missing length prefix" if value.bytesize < 4

      count = decode_u32_le(value.byteslice(0, 4))
      body  = value.byteslice(4, value.bytesize - 4)

      expected = count * EXTRA_META_SIZE
      if body.bytesize < expected
        raise ResolutionError, "PodSlice truncated: need #{expected} bytes, have #{body.bytesize}"
      end

      (0...count).map do |i|
        rec = body.byteslice(i * EXTRA_META_SIZE, EXTRA_META_SIZE)
        {
          discriminator: rec.getbyte(0),
          address_config: rec.byteslice(1, 32),
          signer:   rec.getbyte(33) != 0,
          writable: rec.getbyte(34) != 0
        }
      end
    end

    # ---- Address resolution per meta --------------------------------------

    def resolve_address(meta, resolved, ix_data, hook_program_id)
      disc = meta[:discriminator]

      case disc
      when 0
        # Static address: address_config IS the 32-byte pubkey.
        Addresses.encode_address(meta[:address_config])
      when 1
        # PDA off the transfer hook program itself.
        seeds = unpack_seeds(meta[:address_config], resolved, ix_data)
        derive_pda(hook_program_id, seeds)
      else
        # (128 + i): PDA off the program at index i in the running account list.
        raise ResolutionError, "unexpected meta discriminator #{disc}" if disc < 128
        program_index = disc - 128
        program = resolved.fetch(program_index) do
          raise ResolutionError, "external-PDA program index #{program_index} out of range"
        end
        seeds = unpack_seeds(meta[:address_config], resolved, ix_data)
        derive_pda(program[:pubkey], seeds)
      end
    end

    # ---- Seed unpacking ----------------------------------------------------

    # address_config is a 32-byte buffer holding a sequence of packed Seed
    # entries, terminated by a 0 (Uninitialized) byte or the end of buffer.
    # Returns an ordered array of binary seed strings ready for PDA derivation.
    def unpack_seeds(address_config, resolved, ix_data)
      seeds = []
      i = 0
      bytes = address_config
      len = bytes.bytesize

      while i < len
        variant = bytes.getbyte(i)
        break if variant == SEED_UNINITIALIZED

        case variant
        when SEED_LITERAL
          # 1 byte variant, 1 byte length, then `length` literal bytes.
          length = bytes.getbyte(i + 1)
          seeds << bytes.byteslice(i + 2, length)
          i += 2 + length

        when SEED_INSTRUCTION_DATA
          # 1 byte variant, 1 byte index (offset), 1 byte length.
          index  = bytes.getbyte(i + 1)
          length = bytes.getbyte(i + 2)
          seeds << ix_data.byteslice(index, length)
          i += 3

        when SEED_ACCOUNT_KEY
          # 1 byte variant, 1 byte account index. Seed = that account's 32-byte key.
          index = bytes.getbyte(i + 1)
          acct = resolved.fetch(index) do
            raise ResolutionError, "AccountKey seed index #{index} not yet resolved"
          end
          seeds << Addresses.decode_address(Addresses.address(acct[:pubkey]))
          i += 2

        when SEED_ACCOUNT_DATA
          # 1 byte variant, 1 byte account_index, 1 byte data_index, 1 byte length.
          account_index = bytes.getbyte(i + 1)
          data_index    = bytes.getbyte(i + 2)
          length        = bytes.getbyte(i + 3)
          acct = resolved.fetch(account_index) do
            raise ResolutionError, "AccountData seed index #{account_index} not yet resolved"
          end
          acct_data = fetch_account_data!(acct[:pubkey])
          seeds << acct_data.byteslice(data_index, length)
          i += 4

        else
          raise ResolutionError, "unknown Seed variant #{variant}"
        end
      end

      seeds
    end

    # ---- Helpers -----------------------------------------------------------

    def derive_pda(program_id, seeds)
      pda = Addresses.get_program_derived_address(
        program_address: Addresses.address(program_id),
        seeds: seeds
      )
      pda.address.to_s
    end

    # AccountMeta shape used across the ioniqx client. Kept as a Hash carrying
    # the raw pubkey string so later seeds can read [:pubkey] by index; convert
    # to the kit's AccountMeta value type at instruction-assembly time.
    def account_meta(pubkey, writable:, signer:)
      { pubkey: pubkey.to_s, writable: writable, signer: signer }
    end

    # Lower `meta`'s privileges to the highest already granted to the same
    # address elsewhere in the list. An address absent from the list keeps
    # whatever the validation account asked for - it is new to this
    # instruction, so there is no prior grant to exceed.
    def de_escalate(meta, existing)
      matches = existing.select { |m| m[:pubkey] == meta[:pubkey] }
      return meta if matches.empty?

      {
        pubkey:   meta[:pubkey],
        writable: meta[:writable] && matches.any? { |m| m[:writable] },
        signer:   meta[:signer]   && matches.any? { |m| m[:signer] }
      }
    end

    # Response shape pinned to the kit (§5.3). `Rpc::Client#get_account_info`
    # returns an RpcTypes::RpcContextualValue whose `.value` is an
    # RpcTypes::AccountInfoWithBase64Data - or nil when the account does not
    # exist - and whose `.data` is the JSON-RPC tuple [base64_string, "base64"].
    # The Hash / bare-string branches stay only to tolerate a caller-supplied
    # RPC double.
    def fetch_account_data!(pubkey)
      resp  = @rpc.get_account_info(Addresses.address(pubkey).to_s, encoding: "base64")
      value = resp.respond_to?(:value) ? resp.value : resp
      raise ResolutionError, "account not found: #{pubkey}" if value.nil?

      encoded = value.respond_to?(:data) ? value.data : value["data"]
      b64, encoding = encoded.is_a?(Array) ? encoded : [encoded, "base64"]

      unless encoding.nil? || encoding == "base64"
        raise ResolutionError, "account #{pubkey} returned #{encoding.inspect}-encoded data, expected base64"
      end
      raise ResolutionError, "account #{pubkey} returned no data" if b64.nil?

      Base64.decode64(b64)
    end

    # Codec#decode returns a [value, bytes_consumed] tuple, not the value.
    def decode_u32_le(bytes)
      U32_LE.decode(bytes).first
    end
  end
end
