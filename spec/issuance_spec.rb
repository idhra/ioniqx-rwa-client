# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"

# Golden vectors for the write side (BUILD.md §2.6 build task 1).
#
# The strongest assertion available offline is the round trip: every payload
# encoded here is decoded by the reader in classification.rb, which is itself
# pinned to the devnet reference accounts. If either side drifts in field order
# or encoding, the pair stops agreeing.
RSpec.describe IoniqxRwa::Classification::Issuance do
  Roles = Solana::Ruby::Kit::Instructions::AccountRole

  def b58(seed_byte) = Addresses.encode_address(seed_byte.chr * 32)

  let(:payer)     { b58(0x01) }
  let(:authority) { b58(0x02) }
  let(:signer)    { b58(0x07) }
  let(:commit)    { "\x09".b * 32 }

  let(:fields) do
    {
      asset_class: "real-estate", claim: "equity", subclass: "multifamily",
      jurisdiction: "US-TX", issuer_lei: "549300E9PC51EN656011",
      property_commit: commit,
      discovery_url: "https://rwa1.ioniqx.io/.well-known/rwa.json",
      discovery_signer: signer
    }
  end

  describe ".encode_payload" do
    it "round-trips through the reader's decoder" do
      raw = described_class.encode_payload(mint: REF_MINT, **fields)
      decoded = IoniqxRwa::Classification.decode_payload(raw)

      expect(decoded[:mint]).to eq(REF_MINT)
      expect(decoded[:class]).to eq("real-estate")
      expect(decoded[:claim]).to eq("equity")
      expect(decoded[:subclass]).to eq("multifamily")
      expect(decoded[:jurisdiction]).to eq("US-TX")
      expect(decoded[:issuer_lei]).to eq("549300E9PC51EN656011")
      expect(decoded[:property_commit]).to eq(commit)
      expect(decoded[:discovery_url]).to eq("https://rwa1.ioniqx.io/.well-known/rwa.json")
      expect(decoded[:discovery_signer]).to eq(signer)
    end

    it "produces the 228-byte figure the draft states for a full attestation" do
      expect(described_class.encode_payload(mint: REF_MINT, **fields).bytesize).to eq(228)
    end

    it "writes absent optional strings as empty, not as omitted fields" do
      # Borsh is positional - there is no absent field, only an empty one.
      raw = described_class.encode_payload(
        mint: REF_MINT, asset_class: "treasury", claim: "debt-senior"
      )
      decoded = IoniqxRwa::Classification.decode_payload(raw)

      expect(decoded[:subclass]).to eq("")
      expect(decoded[:jurisdiction]).to eq("")
      expect(decoded[:property_commit]).to be_nil    # empty Vec<u8>, not 32 zeros
      expect(decoded[:discovery_signer]).to be_nil
    end

    it "prefers an empty property_commit over a zero-filled one" do
      raw = described_class.encode_payload(
        mint: REF_MINT, asset_class: "treasury", claim: "debt-senior", property_commit: nil
      )

      # A 32-zero-byte commit would be a valid-looking commitment to nothing.
      expect(raw).not_to include("\x00".b * 32)
    end

    it "rejects a property_commit that is neither 32 bytes nor empty" do
      expect {
        described_class.encode_payload(
          mint: REF_MINT, asset_class: "treasury", claim: "debt-senior",
          property_commit: "short".b
        )
      }.to raise_error(described_class::EncodeError, /property_commit is 5 bytes/)
    end

    it "refuses an out-of-set class or claim rather than writing it on chain" do
      # A mint cannot be un-minted, so this fails at build time.
      expect {
        described_class.encode_payload(mint: REF_MINT, asset_class: "houses", claim: "equity")
      }.to raise_error(described_class::EncodeError, /§2.1/)

      expect {
        described_class.encode_payload(mint: REF_MINT, asset_class: "real-estate", claim: "vibes")
      }.to raise_error(described_class::EncodeError, /§2.2/)
    end

    it "requires claim even when class is set - the axes are orthogonal" do
      expect { described_class.encode_payload(mint: REF_MINT, asset_class: "real-estate") }
        .to raise_error(ArgumentError, /claim/)
    end
  end

  describe ".create_attestation_instruction" do
    subject(:ix) do
      described_class.create_attestation_instruction(
        payer: payer, authority: authority, credential: REF_CREDENTIAL,
        schema: REF_SCHEMA, mint: REF_MINT,
        payload: described_class.encode_payload(mint: REF_MINT, **fields),
        expires_at: 1_800_000_000
      )
    end

    it "targets the Solana Attestation Service, not a program of ours" do
      expect(ix.program_address.to_s).to eq("22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG")
    end

    it "orders the six accounts with the roles the program expects" do
      expect(ix.accounts.map { |a| [a.address.to_s, a.role] }).to eq([
        [payer,                                   Roles::WRITABLE_SIGNER],
        [authority,                               Roles::READONLY_SIGNER],
        [REF_CREDENTIAL,                          Roles::READONLY],
        [REF_SCHEMA,                              Roles::READONLY],
        [IoniqxRwa::Classification.attestation_pda(
          credential: REF_CREDENTIAL, schema: REF_SCHEMA, mint: REF_MINT), Roles::WRITABLE],
        ["11111111111111111111111111111111",      Roles::READONLY]
      ])
    end

    it "creates the address the reader derives, closing the write/read loop" do
      created = ix.accounts[4].address.to_s

      expect(created).to eq("G6qArVxuNwL9aC3EpTY443TfVTfyFmKwQhgmnd6rht9b")
    end

    it "lays out the data as u8 disc | nonce | u32 len + payload | i64 expiry" do
      payload = described_class.encode_payload(mint: REF_MINT, **fields)
      data = ix.data

      expect(data.getbyte(0)).to eq(6)                              # SAS u8, not an Anchor hash
      # nonce is a RAW 32-byte address here, unlike the payload's mint field
      # which is a length-prefixed Vec<u8>. The two look alike and differ.
      expect(data.byteslice(1, 32)).to eq(Addresses.decode_address(Addresses.address(REF_MINT)))
      expect(data.byteslice(33, 4).unpack1("V")).to eq(payload.bytesize)
      expect(data.byteslice(37, payload.bytesize)).to eq(payload)
      expect(data.byteslice(37 + payload.bytesize, 8).unpack1("q<")).to eq(1_800_000_000)
      expect(data.bytesize).to eq(1 + 32 + 4 + payload.bytesize + 8)
    end

    it "refuses to build an attestation with no expiry" do
      # Expiry is the load-bearing control, since revocation deletes the
      # account and is indistinguishable from absence (draft §3.2, §3.4).
      expect {
        described_class.create_attestation_instruction(
          payer: payer, authority: authority, credential: REF_CREDENTIAL,
          schema: REF_SCHEMA, mint: REF_MINT, payload: "x".b, expires_at: 0
        )
      }.to raise_error(described_class::EncodeError, /expires_at/)
    end
  end

  describe ".attest" do
    it "encodes, builds, and reports the address in one step" do
      result = described_class.attest(
        payer: payer, authority: authority, credential: REF_CREDENTIAL,
        schema: REF_SCHEMA, mint: REF_MINT, expires_at: 1_800_000_000, **fields
      )

      expect(result[:attestation]).to eq("G6qArVxuNwL9aC3EpTY443TfVTfyFmKwQhgmnd6rht9b")
      expect(IoniqxRwa::Classification.decode_payload(result[:payload])[:mint]).to eq(REF_MINT)
      expect(result[:instruction].accounts.size).to eq(6)
    end

    it "feeds a view the trust resolver accepts as attested" do
      # End-to-end: what issuance writes is what the reader trusts.
      result = described_class.attest(
        payer: payer, authority: authority, credential: REF_CREDENTIAL,
        schema: REF_SCHEMA, mint: REF_MINT, expires_at: 1_800_000_000, **fields
      )

      view = IoniqxRwa::Classification.build_attestation_view(
        address: result[:attestation],
        account: { credential: REF_CREDENTIAL, signer: authority, expiry: 1_800_000_000 },
        payload: IoniqxRwa::Classification.decode_payload(result[:payload])
      )
      trust = IoniqxRwa::Classification.resolve_trust(
        mint: REF_MINT, attestation: view,
        trusted_attesters: [REF_CREDENTIAL], now: 1_700_000_000
      )

      expect(trust).to be_attested
      expect(trust.conflicts).to be_empty
    end
  end
end
