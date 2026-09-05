# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "base64"

module SpecSupport
  # Stands in for Solana::Ruby::Kit::Rpc::Client, returning pre-seeded account
  # data by pubkey. Mirrors the kit's real response shape exactly: an object
  # with `.value`, whose `.data` is the JSON-RPC [base64_string, "base64"]
  # tuple (BUILD.md §5.3).
  class FakeRpc
    Value = Struct.new(:data)
    Resp  = Struct.new(:value)

    # Every commitment this double was asked for, in call order. The gem
    # reading at the endpoint's default rather than the caller's commitment is
    # how a freshly issued mint reads back as "account not found", so which
    # commitment goes out is behaviour worth asserting.
    attr_reader :commitments

    # @param store [Hash{String => String}] base58 pubkey => raw binary data
    def initialize(store)
      @store = store
      @commitments = []
    end

    def get_account_info(pubkey, encoding: "base64", commitment: nil)
      @commitments << commitment
      raw = @store[pubkey.to_s]
      return Resp.new(nil) if raw.nil?

      Resp.new(Value.new([Base64.strict_encode64(raw), "base64"]))
    end
  end
end
