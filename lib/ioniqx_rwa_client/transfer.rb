# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "solana/ruby/kit"

require_relative "errors"
require_relative "extra_account_metas"

module IoniqxRwa
  # Builds Token-2022 `TransferChecked` instructions that carry the accounts a
  # transfer hook needs.
  #
  # BUILD.md §2.7 Section 4.3 is blunt about why this exists: "Every client that
  # transfers this token MUST build the instruction with hook-aware resolution.
  # A plain `transferChecked` will omit the extra accounts and fail."
  #
  # That failure is not a graceful one and it is not obvious. Token-2022 cannot
  # invoke the hook without the accounts, so the transfer aborts with an error
  # about a missing account rather than anything naming the hook. Every wallet,
  # custodian, and venue that touches an ioniqx RWA token has to do this, which
  # is exactly why it belongs in a client library and not in each caller.
  #
  # The hook program id and the mint's decimals are read off the mint rather
  # than taken on trust. Both are things a caller can get wrong in a way that
  # only shows up as a rejected transaction, and both are already on chain.
  class Transfer
    Addresses    = Solana::Ruby::Kit::Addresses
    Codecs       = Solana::Ruby::Kit::Codecs
    Instructions = Solana::Ruby::Kit::Instructions

    TOKEN_2022_PROGRAM_ID = ExtraAccountMetas::TOKEN_2022_PROGRAM_ID

    # The original SPL Token program. Still the owner of most of what a client
    # will be asked to move — USDC is one of its mints on every cluster — so a
    # client that assumes Token-2022 because ioniqx's own mints use it cannot
    # settle a trade or pay a distribution.
    TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

    TOKEN_PROGRAM_IDS = [ TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID ].freeze

    # `TokenInstruction::TransferChecked` — a single-byte index, not an Anchor
    # discriminator.
    TRANSFER_CHECKED = 12

    # A Token-2022 mint carrying any extension is padded from its 82-byte base
    # to 165 (the size of a token *account*), then carries a 1-byte AccountType
    # discriminator, then TLV entries.
    MINT_BASE_LEN     = 82
    MINT_PADDED_LEN   = 165
    ACCOUNT_TYPE_MINT = 1
    TLV_START         = MINT_PADDED_LEN + 1

    # `ExtensionType::TransferHook`. Its value is an OptionalNonZeroPubkey
    # authority followed by an OptionalNonZeroPubkey program id — all-zero
    # meaning None in both cases.
    EXTENSION_TRANSFER_HOOK = 14

    DECIMALS_OFFSET = 44

    U16_LE = Codecs.u16_codec(endian: :little)
    U32_LE = Codecs.u32_codec(endian: :little)
    U64_LE = Codecs.u64_codec(endian: :little)

    class TransferError < IoniqxRwa::Error
      def self.error_code = :IONIQX__TRANSFER_BUILD_FAILED
    end

    MintInfo = Struct.new(:decimals, :hook_program_id, :token_program_id, keyword_init: true)

    # @param rpc [Solana::Ruby::Kit::Rpc::Client]
    # @param commitment [Symbol, nil] commitment for the mint and validation
    #   reads below; nil sends none and takes the endpoint's default. The
    #   default is `confirmed` and not the endpoint's `finalized` because a
    #   mint issued seconds ago is not finalized yet — see
    #   Config::DEFAULT_COMMITMENT.
    def initialize(rpc, commitment: Config::DEFAULT_COMMITMENT)
      @rpc        = rpc
      @commitment = commitment
      @resolver   = ExtraAccountMetas.new(rpc, commitment: commitment)
    end

    # The commitment this client reads at.
    attr_reader :commitment

    # A `TransferChecked` instruction carrying every account the mint's transfer
    # hook requires.
    #
    # Returns a plain transfer when the mint declares no hook, so a caller can
    # route every SPL transfer through this without branching on whether a
    # particular mint happens to be restricted.
    #
    # @param mint [String]
    # @param source [String]        source token account
    # @param destination [String]   destination token account
    # @param authority [String]     owner or delegate; signs the transfer
    # @param amount [Integer]       in base units
    # @param decimals [Integer,nil] read from the mint when omitted
    # @param hook_program_id [String,nil] read from the mint when omitted
    # @param token_program_id [String,nil] read from the mint's owner when
    #   omitted. Not defaulted to Token-2022: the caller's own mints being
    #   Token-2022 says nothing about the mint in front of it, and a
    #   TransferChecked sent to the wrong token program fails.
    # @param mint_info [MintInfo,nil] a MintInfo already read for this mint.
    #   Supply it to avoid a second read — a caller generally has to look the
    #   mint up before calling, because the associated token accounts are
    #   derived under the mint's own token program.
    # @return [Solana::Ruby::Kit::Instructions::Instruction]
    def transfer_checked(mint:, source:, destination:, authority:, amount:,
                         decimals: nil, hook_program_id: nil,
                         token_program_id: nil, mint_info: nil)
      raise TransferError, "amount must be a non-negative integer" unless amount.is_a?(Integer) && amount >= 0

      info = mint_info
      info ||= self.mint_info(mint) if decimals.nil? || hook_program_id.nil? || token_program_id.nil?

      decimals ||= info.decimals
      hook       = hook_program_id || info&.hook_program_id
      token_program_id ||= info&.token_program_id || TOKEN_2022_PROGRAM_ID

      accounts = [
        meta(source,      writable: true,  signer: false),
        meta(mint,        writable: false, signer: false),
        meta(destination, writable: true,  signer: false),
        meta(authority,   writable: false, signer: true)
      ]

      if hook
        accounts += @resolver.resolve(
          mint:            mint,
          source:          source,
          destination:     destination,
          authority:       authority,
          amount:          amount,
          hook_program_id: hook
        ).map { |m| meta(m[:pubkey], writable: m[:writable], signer: m[:signer]) }
      end

      Instructions::Instruction.new(
        program_address: Addresses.address(token_program_id),
        accounts:        accounts,
        data:            [ TRANSFER_CHECKED ].pack("C") + U64_LE.encode(amount) + [ decimals ].pack("C")
      )
    end

    # The transfer hook program a mint points at, or nil if it declares none.
    #
    # A mint created without the TransferHook extension can never gain one —
    # Token-2022 allocates extension space at account creation — so nil here is
    # permanent, not "not yet".
    def hook_program_for(mint) = mint_info(mint).hook_program_id

    # The token program that owns a mint — `TOKEN_PROGRAM_ID` or
    # `TOKEN_2022_PROGRAM_ID`. Every account this mint has is derived and
    # operated under it.
    def token_program_for(mint) = mint_info(mint).token_program_id

    # Decimals, hook program, and owning token program in one read, because a
    # caller who gets any of the three wrong finds out only when the
    # transaction is rejected.
    def mint_info(mint)
      data, owner = fetch_account!(mint)
      raise TransferError, "#{mint} is not a mint account" if data.bytesize < MINT_BASE_LEN

      if owner && !TOKEN_PROGRAM_IDS.include?(owner)
        raise TransferError, "#{mint} is owned by #{owner}, which is not a token program"
      end

      MintInfo.new(
        decimals:         data.getbyte(DECIMALS_OFFSET),
        hook_program_id:  transfer_hook_program(data),
        # nil when the RPC (or a double) did not report an owner; callers fall
        # back to Token-2022, which is what this client used to assume outright.
        token_program_id: owner
      )
    end

    private

    # Walks the mint's TLV extensions for the TransferHook entry.
    def transfer_hook_program(data)
      return nil if data.bytesize <= MINT_PADDED_LEN
      return nil unless data.getbyte(MINT_PADDED_LEN) == ACCOUNT_TYPE_MINT

      offset = TLV_START
      while offset + 4 <= data.bytesize
        type   = U16_LE.decode(data.byteslice(offset, 2)).first
        length = U16_LE.decode(data.byteslice(offset + 2, 2)).first
        value  = data.byteslice(offset + 4, length)
        offset += 4 + length

        next unless type == EXTENSION_TRANSFER_HOOK
        raise TransferError, "TransferHook extension is #{length} bytes, expected 64" unless length == 64

        # authority occupies the first 32 bytes; the program id follows.
        program_id = value.byteslice(32, 32)
        # OptionalNonZeroPubkey: all-zero is None. A mint can carry the
        # extension with the hook cleared, which makes it unrestricted again.
        return nil if program_id.each_byte.all?(&:zero?)

        return Addresses.encode_address(program_id)
      end

      nil
    end

    def meta(pubkey, writable:, signer:)
      Instructions::AccountMeta.new(
        address: Addresses.address(pubkey.to_s),
        role:    role_for(writable: writable, signer: signer)
      )
    end

    def role_for(writable:, signer:)
      roles = Instructions::AccountRole
      if signer
        writable ? roles::WRITABLE_SIGNER : roles::READONLY_SIGNER
      else
        writable ? roles::WRITABLE : roles::READONLY
      end
    end

    def fetch_account_data!(pubkey) = fetch_account!(pubkey).first

    # Same response shape the resolver pins (BUILD.md §5.3), plus the owner:
    # for a mint that is the token program it belongs to, which decides both
    # the program a transfer is sent to and the addresses its accounts have.
    #
    # @return [Array(String, String|nil)] raw data, owner program (nil when the
    #   response carries none, as a minimal RPC double may not).
    def fetch_account!(pubkey)
      options = { encoding: "base64" }
      options[:commitment] = @commitment if @commitment
      resp  = @rpc.get_account_info(Addresses.address(pubkey.to_s).to_s, **options)
      value = resp.respond_to?(:value) ? resp.value : resp
      raise TransferError, "account not found: #{pubkey}" if value.nil?

      encoded = value.respond_to?(:data) ? value.data : value["data"]
      b64, _encoding = encoded.is_a?(Array) ? encoded : [ encoded, "base64" ]
      raise TransferError, "account #{pubkey} returned no data" if b64.nil?

      # A Struct answers to #[] and then raises on an unknown member, so a
      # double built from one is only safe to subscript when it is a Hash.
      owner =
        if value.respond_to?(:owner)
          value.owner
        elsif value.is_a?(Hash)
          value["owner"] || value[:owner]
        end

      [ Base64.decode64(b64), owner&.to_s ]
    end
  end
end
