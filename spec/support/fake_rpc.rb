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

    # @param store [Hash{String => String}] base58 pubkey => raw binary data
    def initialize(store)
      @store = store
    end

    def get_account_info(pubkey, encoding: "base64")
      raw = @store[pubkey.to_s]
      return Resp.new(nil) if raw.nil?

      Resp.new(Value.new([Base64.strict_encode64(raw), "base64"]))
    end
  end
end
