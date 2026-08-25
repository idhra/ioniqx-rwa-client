# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"

# Golden vectors for the sRFC RWA classification reader (BUILD.md §2.6).
#
# Two kinds of vector here:
#
#   1. Cross-implementation: the PDA derivations are asserted against the
#      devnet reference accounts published in the draft's §3.6, which were
#      created by the TypeScript reference (`npm run sas:devnet`) on sas-lib.
#      Matching them offline proves the Ruby seed order and encodings agree
#      with the TS implementation without touching the network.
#
#   2. Hand-built byte vectors for the Borsh payload, so a reordering of the
#      nine positional fields fails here rather than silently mis-decoding.
RSpec.describe IoniqxRwa::Classification do
  # ---- helpers -------------------------------------------------------------

  def b58(seed_byte) = Addresses.encode_address(seed_byte.chr * 32)

  def u32(n) = [n].pack("V")

  # Borsh String and Vec<u8> share a wire shape: u32 LE length, then bytes.
  def borsh_bytes(str) = u32(str.b.bytesize) + str.b

  # A `rwa.classification.v1` payload, fields in the normative §3.1 order.
  def payload_bytes(mint:, klass:, claim:, subclass:, jurisdiction:,
                    issuer_lei:, property_commit:, discovery_url:, discovery_signer:)
    borsh_bytes(mint) + borsh_bytes(klass) + borsh_bytes(claim) +
      borsh_bytes(subclass) + borsh_bytes(jurisdiction) + borsh_bytes(issuer_lei) +
      borsh_bytes(property_commit) + borsh_bytes(discovery_url) +
      borsh_bytes(discovery_signer)
  end

  # A SAS Attestation account, layout pinned to sas-lib@1.0.10.
  def attestation_account_bytes(nonce:, credential:, schema:, data:, signer:, expiry:)
    [0].pack("C") + nonce + credential + schema +
      u32(data.bytesize) + data + signer + [expiry].pack("q<") + ("\x00".b * 32)
  end

  def schema_account_bytes(credential:, name:, description:, layout:, field_names:,
                           is_paused:, version:)
    [0].pack("C") + credential +
      borsh_bytes(name) + borsh_bytes(description) +
      borsh_bytes(layout) + borsh_bytes(field_names) +
      [is_paused ? 1 : 0].pack("C") + [version].pack("C")
  end

  # ---- Layer 2 addressing: cross-implementation golden vectors -------------

  describe "PDA derivation (draft §3.3, vectors from §3.6)" do
    it "derives the reference schema PDA byte-identically to sas-lib" do
      expect(
        described_class.schema_pda(
          credential: REF_CREDENTIAL, name: "rwa.classification.v1", version: 1
        )
      ).to eq(REF_SCHEMA)
    end

    it "derives the reference attestation PDA with nonce = subject mint" do
      expect(
        described_class.attestation_pda(
          credential: REF_CREDENTIAL, schema: REF_SCHEMA, mint: REF_MINT
        )
      ).to eq(REF_ATTESTATION)
    end

    it "binds the attestation address to the mint, so a different mint derives elsewhere" do
      other = described_class.attestation_pda(
        credential: REF_CREDENTIAL, schema: REF_SCHEMA, mint: b58(0x42)
      )

      expect(other).not_to eq(REF_ATTESTATION)
    end

    it "uses the SAS program id from Config" do
      expect(IoniqxRwa::Config::SAS_PROGRAM_ID)
        .to eq("22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG")
    end
  end

  # ---- Layer 1: metadata parsing ------------------------------------------

  describe ".parse" do
    let(:complete) do
      [
        ["rwa.v", "1"],
        ["rwa.class", "real-estate"],
        ["rwa.claim", "equity"],
        ["rwa.subclass", "multifamily"],
        ["rwa.jurisdiction", "US-TX"],
        ["rwa.issuer_lei", "549300E9PC51EN656011"],
        ["rwa.attestation", REF_ATTESTATION],
        ["rwa.api", "https://rwa.ioniqx.io/.well-known/rwa.json"]
      ]
    end

    it "parses a complete set with no issues" do
      result = described_class.parse(complete)

      expect(result).to be_ok
      expect(result.issues).to be_empty
      expect(result.classification.asset_class).to eq("real-estate")
      expect(result.classification.claim).to eq("equity")
      expect(result.classification.subclass).to eq("multifamily")
      expect(result.classification.jurisdiction).to eq("US-TX")
      expect(result.classification.attestation).to eq(REF_ATTESTATION)
    end

    it "ignores non-rwa keys entirely" do
      result = described_class.parse(complete + [["name", "Tower A"], ["symbol", "TWRA"]])

      expect(result).to be_ok
      expect(result.classification.unrecognized).to be_empty
    end

    it "accepts a Hash and the jsonParsed key/value hash shape" do
      as_hash   = described_class.parse(complete.to_h)
      as_kv     = described_class.parse(complete.map { |k, v| { "key" => k, "value" => v } })

      expect(as_hash.classification).to eq(as_kv.classification)
    end

    it "preserves unrecognized rwa.* keys for forward compatibility" do
      result = described_class.parse(complete + [["rwa.future_field", "x"]])

      expect(result).to be_ok
      expect(result.classification.unrecognized).to eq({ "rwa.future_field" => "x" })
    end

    it "surfaces a duplicate key rather than silently resolving it" do
      result = described_class.parse(complete + [["rwa.class", "treasury"]])

      expect(result).to be_ok
      expect(result.classification.asset_class).to eq("real-estate") # first wins
      expect(result.issues).to include('duplicate key "rwa.class" ignored')
    end

    it "refuses a future version rather than guessing at redefined enums" do
      result = described_class.parse([["rwa.v", "2"], ["rwa.class", "real-estate"], ["rwa.claim", "equity"]])

      expect(result).not_to be_ok
      expect(result.issues.first).to match(/unsupported rwa\.v "2"/)
    end

    it "is fatal on a missing or out-of-set class or claim" do
      expect(described_class.parse([["rwa.v", "1"], ["rwa.claim", "equity"]]).issues)
        .to include("missing rwa.class")

      expect(described_class.parse([["rwa.v", "1"], ["rwa.class", "houses"], ["rwa.claim", "equity"]]).issues)
        .to include('unknown rwa.class "houses"')

      expect(described_class.parse([["rwa.v", "1"], ["rwa.class", "real-estate"], ["rwa.claim", "vibes"]]).issues)
        .to include('unknown rwa.claim "vibes"')
    end

    it "requires claim even though class is present - the axes are orthogonal" do
      result = described_class.parse([["rwa.v", "1"], ["rwa.class", "real-estate"]])

      expect(result).not_to be_ok
      expect(result.issues).to include("missing rwa.claim")
    end

    it "reports but tolerates an unregistered subclass (open registry, §2.3)" do
      result = described_class.parse(complete.map { |k, v| k == "rwa.subclass" ? [k, "houseboat"] : [k, v] })

      expect(result).to be_ok
      expect(result.classification.subclass).to eq("houseboat")
      expect(result.issues).to include('unregistered rwa.subclass "houseboat" for class "real-estate"')
    end

    it "reports a malformed jurisdiction, LEI, and non-https api without failing" do
      result = described_class.parse([
        ["rwa.v", "1"], ["rwa.class", "real-estate"], ["rwa.claim", "equity"],
        ["rwa.jurisdiction", "Texas"], ["rwa.issuer_lei", "NOTALEI"],
        ["rwa.api", "http://rwa.ioniqx.io/.well-known/rwa.json"]
      ])

      expect(result).to be_ok
      expect(result.issues).to include(
        a_string_matching(/malformed rwa\.jurisdiction/),
        a_string_matching(/malformed rwa\.issuer_lei/),
        "rwa.api must be https"
      )
    end

    it "fails when no rwa.* metadata is present at all" do
      expect(described_class.parse([["name", "Tower A"]]).issues).to eq(["no rwa.* metadata present"])
      expect(described_class.parse([])).not_to be_ok
    end
  end

  describe ".well_formed_lei?" do
    # ISO 17442: 20 alphanumerics, ISO 7064 mod-97-10 residue of 1.
    it "accepts checksum-valid LEIs" do
      expect(described_class.well_formed_lei?("549300E9PC51EN656011")).to be true
      expect(described_class.well_formed_lei?("HWUPKR0MPOU8FGXBT394")).to be true
    end

    it "rejects a valid-shaped LEI with a broken checksum" do
      expect(described_class.well_formed_lei?("549300E9PC51EN656012")).to be false
    end

    it "rejects wrong length, lowercase, and non-strings" do
      expect(described_class.well_formed_lei?("549300E9PC51EN65601")).to be false
      expect(described_class.well_formed_lei?("549300e9pc51en656011")).to be false
      expect(described_class.well_formed_lei?(nil)).to be false
    end
  end

  # ---- Layer 2: Borsh payload ---------------------------------------------

  describe ".decode_payload (draft §3.1)" do
    let(:mint_bytes)   { Addresses.decode_address(Addresses.address(REF_MINT)) }
    let(:signer_bytes) { "\x07".b * 32 }
    let(:commit_bytes) { "\x09".b * 32 }

    let(:raw) do
      payload_bytes(
        mint: mint_bytes, klass: "real-estate", claim: "equity",
        subclass: "multifamily", jurisdiction: "US-TX",
        issuer_lei: "549300E9PC51EN656011", property_commit: commit_bytes,
        discovery_url: "https://rwa1.ioniqx.io/.well-known/rwa.json",
        discovery_signer: signer_bytes
      )
    end

    it "decodes all nine positional fields" do
      decoded = described_class.decode_payload(raw)

      expect(decoded[:mint]).to eq(REF_MINT)
      expect(decoded[:class]).to eq("real-estate")
      expect(decoded[:claim]).to eq("equity")
      expect(decoded[:subclass]).to eq("multifamily")
      expect(decoded[:jurisdiction]).to eq("US-TX")
      expect(decoded[:issuer_lei]).to eq("549300E9PC51EN656011")
      expect(decoded[:property_commit]).to eq(commit_bytes)
      expect(decoded[:discovery_url]).to eq("https://rwa1.ioniqx.io/.well-known/rwa.json")
      expect(decoded[:discovery_signer]).to eq(Addresses.encode_address(signer_bytes))
    end

    it "serializes a fully populated attestation to 228 bytes" do
      # Draft §3.1 states the figure; it follows from 3 x (4 + 32) for the
      # Vec<u8> pubkey fields plus 6 x 4 string prefixes plus 96 content chars.
      expect(raw.bytesize).to eq(228)
    end

    it "carries a 32-byte pubkey in 36 bytes, length-prefixed" do
      expect(borsh_bytes("\x01".b * 32).bytesize).to eq(36)
    end

    it "encodes attested bytes rather than decoding the address" do
      # Draft §3.1: a malformed value must fail the comparison, not throw
      # somewhere unrelated - so a short pubkey is a decode error here.
      short = payload_bytes(
        mint: "\x01".b * 31, klass: "treasury", claim: "debt-senior", subclass: "",
        jurisdiction: "US", issuer_lei: "", property_commit: "".b,
        discovery_url: "", discovery_signer: "".b
      )

      expect { described_class.decode_payload(short) }
        .to raise_error(IoniqxRwa::Classification::DecodeError, /mint is 31 bytes/)
    end

    it "treats an empty property_commit as absent, not as a zero commitment" do
      bare = payload_bytes(
        mint: mint_bytes, klass: "treasury", claim: "debt-senior", subclass: "",
        jurisdiction: "US", issuer_lei: "", property_commit: "".b,
        discovery_url: "", discovery_signer: "".b
      )
      decoded = described_class.decode_payload(bare)

      expect(decoded[:property_commit]).to be_nil
      expect(decoded[:discovery_signer]).to be_nil
    end

    it "raises rather than returning plausible values from a truncated buffer" do
      expect { described_class.decode_payload(raw.byteslice(0, 40)) }
        .to raise_error(IoniqxRwa::Classification::DecodeError, /truncated/)
    end

    it "would mis-decode if field order drifted, so order is asserted here" do
      swapped = payload_bytes(
        mint: mint_bytes, klass: "equity", claim: "real-estate", subclass: "multifamily",
        jurisdiction: "US-TX", issuer_lei: "", property_commit: "".b,
        discovery_url: "", discovery_signer: "".b
      )

      expect(described_class.decode_payload(swapped)[:class]).to eq("equity")
    end
  end

  describe ".decode_attestation_account" do
    it "reads expiry from the account's native field, never the payload" do
      data = payload_bytes(
        mint: Addresses.decode_address(Addresses.address(REF_MINT)),
        klass: "real-estate", claim: "equity", subclass: "", jurisdiction: "US",
        issuer_lei: "", property_commit: "".b, discovery_url: "", discovery_signer: "".b
      )
      raw = attestation_account_bytes(
        nonce:      Addresses.decode_address(Addresses.address(REF_MINT)),
        credential: Addresses.decode_address(Addresses.address(REF_CREDENTIAL)),
        schema:     Addresses.decode_address(Addresses.address(REF_SCHEMA)),
        data:       data,
        signer:     "\x05".b * 32,
        expiry:     1_800_000_000
      )

      account = described_class.decode_attestation_account(raw)

      expect(account[:nonce]).to eq(REF_MINT)
      expect(account[:credential]).to eq(REF_CREDENTIAL)
      expect(account[:schema]).to eq(REF_SCHEMA)
      expect(account[:expiry]).to eq(1_800_000_000)
      expect(described_class.decode_payload(account[:data])[:mint]).to eq(REF_MINT)
    end
  end

  describe ".decode_schema_account" do
    let(:raw) do
      schema_account_bytes(
        credential:  Addresses.decode_address(Addresses.address(REF_CREDENTIAL)),
        name:        "rwa.classification.v1",
        description: "RWA asset classification",
        layout:      [13, 12, 12, 12, 12, 12, 13, 12, 13].pack("C*"),
        field_names: "mint",
        is_paused:   false,
        version:     1
      )
    end

    it "reads the pause kill switch and the normative layout codes" do
      schema = described_class.decode_schema_account(raw)

      expect(schema[:name]).to eq("rwa.classification.v1")
      expect(schema[:is_paused]).to be false
      expect(schema[:version]).to eq(1)
      # 12 = String, 13 = Vec<u8>; the §3.1 table in code-point form.
      expect(schema[:layout]).to eq([13, 12, 12, 12, 12, 12, 13, 12, 13])
    end
  end

  # ---- Layer 2: trust resolution ------------------------------------------

  describe ".resolve_trust" do
    let(:mint)       { b58(0x22) }
    let(:trusted)    { b58(0xAA) }
    let(:untrusted)  { b58(0xBB) }
    let(:now)        { 1_700_000_000 }

    let(:classification) do
      described_class.parse([
        ["rwa.v", "1"], ["rwa.class", "real-estate"], ["rwa.claim", "equity"],
        ["rwa.subclass", "multifamily"], ["rwa.jurisdiction", "US-TX"]
      ]).classification
    end

    def attestation(attester: nil, mint_address: nil, expires_at: nil, **overrides)
      described_class::AttestationView.new(**{
        address: b58(0xCC), attester: attester || trusted, signer: b58(0xDD),
        mint: mint_address || mint, asset_class: "real-estate", claim: "equity",
        subclass: "multifamily", jurisdiction: "US-TX", issuer_lei: nil,
        property_commit: nil, discovery_url: nil, discovery_signer: nil,
        expires_at: expires_at || (now + 86_400), schema_paused: false, revoked: false
      }.merge(overrides))
    end

    it "is :unknown with neither metadata nor attestation" do
      assessment = described_class.resolve_trust(mint: mint, trusted_attesters: [trusted], now: now)

      expect(assessment.level).to eq(:unknown)
    end

    it "is :self_declared with metadata but no attestation" do
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification, trusted_attesters: [trusted], now: now
      )

      expect(assessment.level).to eq(:self_declared)
      expect(assessment.reasons).to include("no attestation referenced")
    end

    it "is :attested for an unexpired attestation from a trusted credential" do
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification, attestation: attestation,
        trusted_attesters: [trusted], now: now
      )

      expect(assessment).to be_attested
      expect(assessment.attester).to eq(trusted)
      expect(assessment.conflicts).to be_empty
    end

    it "discards an attestation bound to a different mint outright" do
      # Otherwise any real attestation, replayed against any mint, reads as
      # verified.
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification,
        attestation: attestation(mint_address: b58(0x99)),
        trusted_attesters: [trusted], now: now
      )

      expect(assessment.level).to eq(:self_declared)
      expect(assessment.attester).to be_nil
      expect(assessment.reasons).to include("attestation is bound to a different mint - disregarded")
      expect(assessment.conflicts.first).to match(/\Amint: assessed/)
    end

    it "downgrades an attester outside the trust set to :self_declared" do
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification, attestation: attestation(attester: untrusted),
        trusted_attesters: [trusted], now: now
      )

      expect(assessment.level).to eq(:self_declared)
      expect(assessment.reasons).to include("attester not in trust set")
    end

    it "keeps :expired distinct from :unknown" do
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification, attestation: attestation(expires_at: now - 1),
        trusted_attesters: [trusted], now: now
      )

      expect(assessment.level).to eq(:expired)
      expect(assessment.reasons.last).to match(/attestation expired at/)
    end

    it "treats a paused schema as no better than unattested (§3.4)" do
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification, attestation: attestation(schema_paused: true),
        trusted_attesters: [trusted], now: now
      )

      expect(assessment.level).to eq(:self_declared)
      expect(assessment.reasons).to include("schema is paused")
    end

    it "flags self-attestation without silently discarding it (§3.5)" do
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification, attestation: attestation,
        trusted_attesters: [trusted], mint_authorities: [trusted], now: now
      )

      expect(assessment).to be_attested
      expect(assessment).to be_self_attested
      expect(assessment.reasons).to include("attester is also a mint authority - not independent review")
    end

    it "surfaces metadata/attestation field conflicts without picking a side" do
      assessment = described_class.resolve_trust(
        mint: mint, classification: classification,
        attestation: attestation(jurisdiction: "US-NY", subclass: "office"),
        trusted_attesters: [trusted], now: now
      )

      expect(assessment).to be_attested
      expect(assessment.conflicts).to contain_exactly(
        'subclass: metadata "multifamily" vs attestation "office"',
        'jurisdiction: metadata "US-TX" vs attestation "US-NY"'
      )
      expect(assessment.reasons).to include("metadata disagrees with attestation")
    end

    it "keys trust on the credential, not the rotatable signer" do
      # signer differs from every trusted entry; attester (credential) matches.
      assessment = described_class.resolve_trust(
        mint: mint, attestation: attestation(signer: b58(0xEE)),
        trusted_attesters: [trusted], now: now
      )

      expect(assessment).to be_attested
    end
  end

  # ---- Layer 3: discovery --------------------------------------------------

  describe ".parse_discovery_document" do
    let(:mint) { b58(0x22) }
    let(:now)  { 1_700_000_000 }

    def doc(**overrides)
      JSON.generate({
        "version" => "1", "mint" => mint,
        "issued_at" => "2026-08-01T00:00:00Z", "expires_at" => "2027-08-01T00:00:00Z",
        "manifest" => "bagaaiera...",
        "endpoints" => { "nav" => "https://rwa.ioniqx.io/nav" }
      }.merge(overrides))
    end

    it "parses a well-formed document" do
      result = described_class.parse_discovery_document(doc, mint: mint, now: now)

      expect(result).to be_ok
      expect(result.issues).to be_empty
      expect(result.document.endpoints).to eq({ "nav" => "https://rwa.ioniqx.io/nav" })
    end

    it "rejects a document bound to another mint, blocking replay" do
      result = described_class.parse_discovery_document(doc(**{ "mint" => b58(0x99) }), mint: mint, now: now)

      expect(result).not_to be_ok
      expect(result.issues.first).to match(/mint mismatch/)
    end

    it "also accepts the reference implementation's camelCase keys" do
      # SPEC §4.2 shows snake_case; the TS reference reads camelCase and has no
      # test for it. Spec form is canonical, camelCase is tolerated.
      camel = JSON.generate({
        "version" => "1", "mint" => mint,
        "issuedAt" => "2026-08-01T00:00:00Z", "expiresAt" => "2027-08-01T00:00:00Z",
        "endpoints" => {}
      })
      result = described_class.parse_discovery_document(camel, mint: mint, now: now)

      expect(result).to be_ok
      expect(result.document.expires_at).to eq("2027-08-01T00:00:00Z")
    end

    it "rejects invalid JSON, a non-object, and an unsupported version" do
      expect(described_class.parse_discovery_document("{", mint: mint, now: now).issues)
        .to eq(["discovery document is not valid JSON"])
      expect(described_class.parse_discovery_document("[]", mint: mint, now: now).issues)
        .to eq(["discovery document is not an object"])
      expect(described_class.parse_discovery_document(doc(**{ "version" => "2" }), mint: mint, now: now))
        .not_to be_ok
    end

    it "reports expiry as an issue but still returns the document" do
      result = described_class.parse_discovery_document(doc, mint: mint, now: 1_900_000_000)

      expect(result).to be_ok
      expect(result.issues.first).to match(/discovery document expired at/)
    end

    it "drops non-https endpoints rather than passing them through" do
      result = described_class.parse_discovery_document(
        doc(**{ "endpoints" => { "nav" => "http://rwa.ioniqx.io/nav", "ok" => "https://rwa.ioniqx.io/ok" } }),
        mint: mint, now: now
      )

      expect(result.document.endpoints.keys).to eq(["ok"])
      expect(result.issues).to include('endpoint "nav" is not an https URL - dropped')
    end
  end

  describe ".verify_discovery_document" do
    let(:signing_key) { RbNaCl::SigningKey.generate }
    let(:signer_b58)  { Addresses.encode_address(signing_key.verify_key.to_bytes) }
    let(:raw)         { '{"version":"1"}'.b }

    def attestation_with(signer)
      described_class::AttestationView.new(
        address: b58(0xCC), attester: b58(0xAA), signer: b58(0xDD), mint: b58(0x22),
        asset_class: "real-estate", claim: "equity", subclass: nil, jurisdiction: nil,
        issuer_lei: nil, property_commit: nil, discovery_url: nil,
        discovery_signer: signer, expires_at: 1_900_000_000,
        schema_paused: false, revoked: false
      )
    end

    before { require "rbnacl" }

    it "verifies a detached signature over the exact bytes as served" do
      signature = signing_key.sign(raw)

      result = described_class.verify_discovery_document(raw, signature, attestation_with(signer_b58))

      expect(result).to be_verified
      expect(result.reason).to eq("signed by the attested discovery key")
    end

    it "rejects a signature over even a whitespace-different body" do
      # No canonicalization, per §4.1: every divergence between two JSON
      # canonicalizers is a bypass.
      signature = signing_key.sign('{"version": "1"}'.b)

      result = described_class.verify_discovery_document(raw, signature, attestation_with(signer_b58))

      expect(result).not_to be_verified
    end

    it "rejects a signature from a key the attestation did not authorize" do
      signature = RbNaCl::SigningKey.generate.sign(raw)

      expect(described_class.verify_discovery_document(raw, signature, attestation_with(signer_b58)))
        .not_to be_verified
    end

    it "refuses when the attestation names no discovery signer" do
      result = described_class.verify_discovery_document(raw, "x".b * 64, attestation_with(nil))

      expect(result).not_to be_verified
      expect(result.reason).to eq("attestation names no discovery signer")
    end

    it "converts a throwing verifier into a failed verification" do
      result = described_class.verify_discovery_document(raw, "too short".b, attestation_with(signer_b58))

      expect(result).not_to be_verified
      expect(result.reason).to match(/verification threw/)
    end
  end

  # ---- Display -------------------------------------------------------------

  describe "display helpers" do
    it "never collapses expired into unknown" do
      expect(described_class.trust_label(:attested)).to eq("Verified")
      expect(described_class.trust_label(:expired)).to eq("Verification expired")
      expect(described_class.trust_label(:self_declared)).to eq("Self-declared")
      expect(described_class.trust_label(:unknown)).to eq("Unidentified")
    end

    it "summarizes the two enum axes, preferring subclass over class" do
      with_subclass = described_class.parse([
        ["rwa.v", "1"], ["rwa.class", "real-estate"], ["rwa.claim", "equity"],
        ["rwa.subclass", "multifamily"]
      ]).classification
      without = described_class.parse([
        ["rwa.v", "1"], ["rwa.class", "private-credit"], ["rwa.claim", "debt-senior"]
      ]).classification

      expect(described_class.describe(with_subclass)).to eq("Multifamily · Equity")
      expect(described_class.describe(without)).to eq("Private Credit · Debt Senior")
    end
  end

  # ---- Reader: fetch + decode ---------------------------------------------

  describe IoniqxRwa::Classification::Reader do
    let(:mint) { REF_MINT }

    let(:payload) do
      payload_bytes(
        mint: Addresses.decode_address(Addresses.address(REF_MINT)),
        klass: "real-estate", claim: "equity", subclass: "multifamily",
        jurisdiction: "US-TX", issuer_lei: "", property_commit: "".b,
        discovery_url: "https://rwa.ioniqx.io/.well-known/rwa.json",
        discovery_signer: "\x07".b * 32
      )
    end

    def store(paused: false, with_attestation: true)
      s = {}
      s[REF_SCHEMA] = schema_account_bytes(
        credential: Addresses.decode_address(Addresses.address(REF_CREDENTIAL)),
        name: "rwa.classification.v1", description: "", layout: "".b,
        field_names: "".b, is_paused: paused, version: 1
      )
      if with_attestation
        s[REF_ATTESTATION] = attestation_account_bytes(
          nonce:      Addresses.decode_address(Addresses.address(REF_MINT)),
          credential: Addresses.decode_address(Addresses.address(REF_CREDENTIAL)),
          schema:     Addresses.decode_address(Addresses.address(REF_SCHEMA)),
          data: payload, signer: "\x05".b * 32, expiry: 1_800_000_000
        )
      end
      s
    end

    it "finds an attestation by derivation alone, with no indexer" do
      view = described_class.new(SpecSupport::FakeRpc.new(store))
                            .attestation_for(mint: mint, credential: REF_CREDENTIAL)

      expect(view.address).to eq(REF_ATTESTATION)
      expect(view.attester).to eq(REF_CREDENTIAL)   # credential, not signer
      expect(view.signer).to eq(Addresses.encode_address("\x05".b * 32))
      expect(view.mint).to eq(REF_MINT)
      expect(view.asset_class).to eq("real-estate")
      expect(view.expires_at).to eq(1_800_000_000)
      expect(view.schema_paused).to be false
      expect(view.issuer_lei).to be_nil  # empty string is absence, not ""
    end

    it "returns nil when no attestation exists" do
      view = described_class.new(SpecSupport::FakeRpc.new(store(with_attestation: false)))
                            .attestation_for(mint: mint, credential: REF_CREDENTIAL)

      expect(view).to be_nil
    end

    it "carries the schema pause flag through to the view" do
      view = described_class.new(SpecSupport::FakeRpc.new(store(paused: true)))
                            .attestation_for(mint: mint, credential: REF_CREDENTIAL)

      expect(view.schema_paused).to be true
    end

    it "treats an unreadable schema as paused rather than as absent" do
      expect(described_class.new(SpecSupport::FakeRpc.new({})).schema_paused?(REF_SCHEMA)).to be true
    end
  end
end
