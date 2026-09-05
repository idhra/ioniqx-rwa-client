# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"
require "json"
require "base64"
require "ioniqx_rwa_client/transfer"
require "ioniqx_rwa_client/classification"

# What commitment this gem reads at.
#
# Solana's RPC default is `finalized`, ~32 slots behind the tip. Every account
# this gem reads is one the caller was just handed — the mint it is
# transferring, the validation account written when that mint was configured —
# so a finalized read of a freshly issued mint returns nothing, and the caller
# sees `account not found` for an account that plainly exists. This is not
# hypothetical: it is how the first devnet issuance out of the ioniqx Rails app
# failed, seconds after the mint landed at `confirmed`.
# A constant assigned inside a describe block lands on Object, so this file
# uses none — two spec files already own FIXTURE and FIXTURE_PATH.
RSpec.describe "read commitment" do
  let(:fixture) do
    JSON.parse(File.read(File.expand_path("fixtures/client_resolution.json", __dir__)))
  end

  let(:accounts) do
    fixture["account_data"].each_with_object({}) do |(pubkey, b64), store|
      store[pubkey] = Base64.decode64(b64)
    end
  end

  let(:rpc) { SpecSupport::FakeRpc.new(accounts) }

  def build_transfer(client)
    client.transfer_checked(
      mint:            fixture["mint"],
      source:          fixture["source"],
      destination:     fixture["destination"],
      authority:       fixture["authority"],
      amount:          fixture["amount"]
    )
  end

  it "defaults to confirmed rather than the endpoint's finalized" do
    expect(IoniqxRwa::Config::DEFAULT_COMMITMENT).to eq(:confirmed)
    expect(IoniqxRwa::Transfer.new(rpc).commitment).to eq(:confirmed)
    expect(IoniqxRwa::ExtraAccountMetas.new(rpc).commitment).to eq(:confirmed)
  end

  it "sends that commitment on every read a transfer makes" do
    build_transfer(IoniqxRwa::Transfer.new(rpc))

    expect(rpc.commitments).not_to be_empty
    expect(rpc.commitments.uniq).to eq([:confirmed])
  end

  # The mint read and the validation read go through different objects; a
  # commitment set on the client has to reach the resolver it builds.
  it "passes the caller's commitment down to the resolver" do
    build_transfer(IoniqxRwa::Transfer.new(rpc, commitment: :processed))

    expect(rpc.commitments.uniq).to eq([:processed])
  end

  it "sends no commitment at all when given nil" do
    build_transfer(IoniqxRwa::Transfer.new(rpc, commitment: nil))

    expect(rpc.commitments.uniq).to eq([nil])
  end

  # An RPC double with the older two-argument signature is still usable — the
  # kwarg goes out only when there is a commitment to send.
  it "does not force the kwarg on a double that predates it" do
    value_struct = Struct.new(:data)
    resp_struct  = Struct.new(:value)
    store        = accounts

    legacy = Object.new
    legacy.define_singleton_method(:get_account_info) do |pubkey, encoding: "base64"|
      raw = store[pubkey.to_s]
      next resp_struct.new(nil) if raw.nil?

      resp_struct.new(value_struct.new([Base64.strict_encode64(raw), encoding]))
    end

    expect { build_transfer(IoniqxRwa::Transfer.new(legacy, commitment: nil)) }.not_to raise_error
  end

  it "reads classification attestations at the same commitment" do
    reader = IoniqxRwa::Classification::Reader.new(rpc)
    reader.attestation_for(mint: fixture["mint"], credential: fixture["authority"])

    expect(rpc.commitments.uniq).to eq([:confirmed])
  end
end
