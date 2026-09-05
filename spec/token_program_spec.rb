# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"
require "ioniqx_rwa_client/transfer"

# Which token program a transfer is sent to.
#
# ioniqx issues its own mints under Token-2022, because that is where transfer
# hooks live. Nothing follows from that about the mints it has to *move*: USDC,
# the settlement asset for every subscription and every distribution, is an
# original SPL Token mint on devnet and on mainnet alike. A client that assumes
# Token-2022 derives the wrong associated token accounts and sends
# TransferChecked to a program that does not own the mint.
#
# The mint account says who owns it. Read that instead of assuming.
RSpec.describe "token program detection" do
  let(:mint)        { "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" }
  let(:source)      { "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM" }
  let(:destination) { "So11111111111111111111111111111111111111112" }
  let(:authority)   { "SysvarC1ock11111111111111111111111111111111" }

  # An original-SPL-Token mint: 82 bytes, decimals at offset 44, no extensions.
  def plain_mint(decimals: 6)
    bytes = +("\x00".b * 82)
    bytes.setbyte(44, decimals)
    bytes
  end

  def rpc_for(owner, data: plain_mint)
    SpecSupport::FakeRpc.new({ mint => data }, owners: { mint => owner })
  end

  def build(client, **overrides)
    client.transfer_checked(
      mint: mint, source: source, destination: destination,
      authority: authority, amount: 1_000, **overrides
    )
  end

  it "sends a Token-2022 mint's transfer to Token-2022" do
    client = IoniqxRwa::Transfer.new(rpc_for(IoniqxRwa::Transfer::TOKEN_2022_PROGRAM_ID))

    expect(build(client).program_address.to_s).to eq(IoniqxRwa::Transfer::TOKEN_2022_PROGRAM_ID)
  end

  it "sends an original-Token mint's transfer to that program" do
    client = IoniqxRwa::Transfer.new(rpc_for(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID))

    expect(build(client).program_address.to_s).to eq(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID)
  end

  it "reports the owning program for a mint" do
    client = IoniqxRwa::Transfer.new(rpc_for(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID))

    expect(client.token_program_for(mint)).to eq(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID)
    expect(client.mint_info(mint).decimals).to eq(6)
  end

  it "refuses a mint owned by something that is not a token program" do
    client = IoniqxRwa::Transfer.new(rpc_for("11111111111111111111111111111111"))

    expect { build(client) }
      .to raise_error(IoniqxRwa::Transfer::TransferError, /not a token program/)
  end

  it "lets the caller override the detected program" do
    client = IoniqxRwa::Transfer.new(rpc_for(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID))
    instruction = build(client, token_program_id: IoniqxRwa::Transfer::TOKEN_2022_PROGRAM_ID)

    expect(instruction.program_address.to_s).to eq(IoniqxRwa::Transfer::TOKEN_2022_PROGRAM_ID)
  end

  # An RPC double that reports no owner is not an error — the gem falls back to
  # what it used to assume unconditionally.
  it "falls back to Token-2022 when the response carries no owner" do
    client = IoniqxRwa::Transfer.new(SpecSupport::FakeRpc.new({ mint => plain_mint }))

    expect(build(client).program_address.to_s).to eq(IoniqxRwa::Transfer::TOKEN_2022_PROGRAM_ID)
  end

  # The caller has to read the mint before calling — the token accounts it
  # passes are derived under the mint's own program — so it can hand the result
  # over rather than pay for the same round trip twice.
  it "does not re-read the mint when handed a MintInfo" do
    rpc    = rpc_for(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID)
    client = IoniqxRwa::Transfer.new(rpc)
    info   = client.mint_info(mint)
    rpc.reads.clear

    instruction = build(client, mint_info: info)

    expect(rpc.reads).to be_empty
    expect(instruction.program_address.to_s).to eq(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID)
  end

  it "carries the mint's decimals into the instruction either way" do
    client = IoniqxRwa::Transfer.new(rpc_for(IoniqxRwa::Transfer::TOKEN_PROGRAM_ID,
                                             data: plain_mint(decimals: 9)))

    expect(build(client).data.bytes.last).to eq(9)
  end
end
