# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "base64"

module SpecSupport
  # Stands in for Solana::Ruby::Kit::Rpc::Client, returning pre-seeded account
  # data by pubkey. Mirrors the kit's real response shape exactly: an object
  # with `.value`, whose `.data` is the JSON-RPC [base64_string, "base64"]
  # tuple (BUILD.md §5.3).
  class FakeRpc
    Value = Struct.new(:data, :owner)
    Resp  = Struct.new(:value)

    # Every commitment this double was asked for, in call order. The gem
    # reading at the endpoint's default rather than the caller's commitment is
    # how a freshly issued mint reads back as "account not found", so which
    # commitment goes out is behaviour worth asserting.
    attr_reader :commitments

    # Every pubkey this double was asked for, in call order. A caller that
    # reads the same mint twice is paying for a round trip it was handed the
    # answer to.
    attr_reader :reads

    # @param store [Hash{String => String}] base58 pubkey => raw binary data
    # @param owners [Hash{String => String}] base58 pubkey => owning program.
    #   Left empty, accounts report no owner, which is what a minimal RPC
    #   double does and what the gem has to tolerate.
    def initialize(store, owners: {})
      @store = store
      @owners = owners
      @commitments = []
      @reads = []
    end

    def get_account_info(pubkey, encoding: "base64", commitment: nil)
      @commitments << commitment
      @reads << pubkey.to_s
      raw = @store[pubkey.to_s]
      return Resp.new(nil) if raw.nil?

      Resp.new(Value.new([Base64.strict_encode64(raw), "base64"], @owners[pubkey.to_s]))
    end
  end
end
