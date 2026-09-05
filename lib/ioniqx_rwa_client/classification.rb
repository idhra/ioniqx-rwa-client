# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "base64"
require "json"
require "time"

require "solana/ruby/kit"

require_relative "errors"
require_relative "config"

module IoniqxRwa
  # Read-side reader for the sRFC "RWA Asset Classification and Data Discovery"
  # convention (BUILD.md §2.6). Ruby port of the reference reader in
  # pzupan/rwa-classification, `src/rwa-classification.ts`.
  #
  # THE LOAD-BEARING RULE, from §5 of the draft: nothing here is an
  # authorization decision. Transfer eligibility is enforced on-chain by the
  # token's own extensions - the five ioniqx Anchor programs. This module only
  # decides how much to trust a *description*. Do not wire any value it returns
  # into a transfer path, a holder-group assignment, or a compliance gate.
  #
  # Layout mirrors the reference: pure functions over data you have already
  # fetched, with the one impure piece (RPC) isolated in {Reader} and signature
  # verification left as an injected seam. Field order and encodings are pinned
  # to `sas-lib@1.0.10`, since Borsh is positional.
  module Classification
    Addresses = Solana::Ruby::Kit::Addresses
    Codecs    = Solana::Ruby::Kit::Codecs

    U32_LE = Codecs.u32_codec(endian: :little)
    I64_LE = Codecs.i64_codec(endian: :little)

    class DecodeError < IoniqxRwa::Error
      def self.error_code = :IONIQX__CLASSIFICATION_DECODE_FAILED
    end

    # ---- Vocabulary --------------------------------------------------------

    # Closed set (draft §2.1). Additions require a version bump.
    RWA_CLASSES = %w[
      real-estate
      treasury
      corporate-credit
      private-credit
      public-equity
      private-equity
      commodity
      fund
      carbon
      receivable
      other
    ].freeze

    # Closed set (draft §2.2). Orthogonal to the class and always required: a
    # mortgage note and an equity stake in the same building are both
    # `real-estate` with inverted risk.
    RWA_CLAIMS = %w[
      equity
      preferred-equity
      debt-senior
      debt-mezzanine
      fund-lp
      revenue-share
      direct-title
      derivative
    ].freeze

    # Open registry (draft §2.3) - unknown values are surfaced, not rejected.
    # The real-estate vocabulary tracks the NCREIF/NAREIT core property types.
    RWA_SUBCLASSES = {
      "real-estate" => %w[
        multifamily industrial office retail hospitality self-storage
        data-center senior-housing single-family-rental land mixed-use specialty
      ].freeze,
      "treasury"         => %w[bill note bond money-market].freeze,
      "corporate-credit" => %w[investment-grade high-yield convertible].freeze,
      "private-credit"   => %w[direct-lending mezzanine venture-debt].freeze,
      "public-equity"    => [].freeze,
      "private-equity"   => %w[buyout growth venture].freeze,
      "commodity"        => %w[metal energy agricultural].freeze,
      "fund"             => %w[open-end closed-end interval].freeze,
      "carbon"           => %w[removal avoidance].freeze,
      "receivable"       => %w[trade invoice royalty].freeze,
      "other"            => [].freeze
    }.freeze

    # Draft version this reader implements.
    SUPPORTED_VERSION = "1"

    # `rwa.*` keys this reader knows. Anything else is preserved verbatim in
    # Descriptor#unrecognized rather than dropped, for forward compatibility.
    KNOWN_KEYS = %w[
      rwa.v rwa.class rwa.claim rwa.subclass rwa.jurisdiction
      rwa.issuer_lei rwa.attestation rwa.api
    ].freeze

    JURISDICTION_RE = /\A[A-Z]{2}(-[A-Z0-9]{1,3})?\z/
    LEI_RE          = /\A[0-9A-Z]{20}\z/

    # ---- Value types -------------------------------------------------------

    # Parsed `rwa.*` keys from a Token-2022 mint's `additionalMetadata`.
    # Equivalent to the reference's `Classification` type.
    Descriptor = Data.define(
      :version, :asset_class, :claim, :subclass, :jurisdiction,
      :issuer_lei, :attestation, :api_url, :unrecognized
    )

    ParseResult = Data.define(:ok, :classification, :issues) do
      def ok? = ok
    end

    # The fields this convention needs from a decoded SAS attestation.
    #
    # Pubkey-valued payload fields arrive as 32 raw bytes and are base58-encoded
    # here, per draft §3.1: consumers compare by encoding the attested bytes,
    # never by decoding the address, so a malformed value fails the comparison
    # instead of raising.
    AttestationView = Data.define(
      :address, :attester, :signer, :mint, :asset_class, :claim, :subclass,
      :jurisdiction, :issuer_lei, :property_commit, :discovery_url,
      :discovery_signer, :expires_at, :schema_paused, :revoked
    ) do
      def expired?(now = Time.now.to_i) = expires_at <= now

      # True when the attesting credential is one of the mint's own authorities
      # - a signature, but not independent review (draft §3.5).
      def self_attested?(mint_authorities)
        Array(mint_authorities).include?(attester)
      end
    end

    TrustAssessment = Data.define(:level, :attester, :self_attested, :conflicts, :reasons) do
      def attested? = level == :attested
      def self_attested? = self_attested
    end

    DiscoveryDocument = Data.define(:version, :mint, :issued_at, :expires_at, :manifest, :endpoints)
    DiscoveryResult   = Data.define(:ok, :document, :issues) do
      def ok? = ok
    end

    Verification = Data.define(:verified, :reason) do
      def verified? = verified
    end

    # Trust levels. Per draft §5, `:expired` must never collapse into
    # `:unknown` - a lapsed issuer and an absent one are different facts.
    TRUST_LEVELS = %i[attested expired self_declared unknown].freeze

    class << self
      # ---- Layer 1 - classification metadata -----------------------------

      # Parse the `rwa.*` subset of a mint's `additionalMetadata`.
      #
      # Accepts the shapes the Token-2022 SDK and `jsonParsed` RPC responses
      # produce: an array of [key, value] pairs, an array of
      # {"key" =>, "value" =>} hashes, or a plain Hash. Non-`rwa.` keys are
      # ignored entirely.
      #
      # Fatal (ok? == false): missing or unsupported `rwa.v`, missing or
      # out-of-set `rwa.class` / `rwa.claim`. Everything else is reported in
      # `issues` while still returning a usable Descriptor.
      #
      # @return [ParseResult]
      def parse(entries)
        issues = []
        fields = {}

        normalize_entries(entries).each do |key, value|
          next unless key.to_s.start_with?("rwa.")

          key = key.to_s
          # First occurrence wins: a duplicate key is a plausible obfuscation
          # trick, so it is surfaced rather than silently resolved.
          if fields.key?(key)
            issues << %(duplicate key "#{key}" ignored)
            next
          end
          fields[key] = value.to_s
        end

        return failure(["no rwa.* metadata present"]) if fields.empty?

        version = fields["rwa.v"]
        return failure(issues + ["missing rwa.v"]) if version.nil?
        unless version == SUPPORTED_VERSION
          # Refuse rather than guess: a later version may redefine these enums.
          return failure(issues + [
            %(unsupported rwa.v "#{version}" (this reader implements #{SUPPORTED_VERSION}))
          ])
        end

        raw_class = fields["rwa.class"]
        return failure(issues + ["missing rwa.class"]) if raw_class.nil?
        return failure(issues + [%(unknown rwa.class "#{raw_class}")]) unless rwa_class?(raw_class)

        raw_claim = fields["rwa.claim"]
        return failure(issues + ["missing rwa.claim"]) if raw_claim.nil?
        return failure(issues + [%(unknown rwa.claim "#{raw_claim}")]) unless rwa_claim?(raw_claim)

        subclass = fields["rwa.subclass"]
        if subclass && !known_subclass?(raw_class, subclass)
          issues << %(unregistered rwa.subclass "#{subclass}" for class "#{raw_class}")
        end

        jurisdiction = fields["rwa.jurisdiction"]
        if jurisdiction && !JURISDICTION_RE.match?(jurisdiction)
          issues << %(malformed rwa.jurisdiction "#{jurisdiction}" (expected ISO 3166 form))
        end

        issuer_lei = fields["rwa.issuer_lei"]
        if issuer_lei && !well_formed_lei?(issuer_lei)
          issues << %(malformed rwa.issuer_lei "#{issuer_lei}" (failed ISO 17442 checksum))
        end

        api_url = fields["rwa.api"]
        issues << "rwa.api must be https" if api_url && !api_url.start_with?("https://")

        unrecognized = fields.reject { |k, _| KNOWN_KEYS.include?(k) }.freeze

        ParseResult.new(
          ok: true,
          issues: issues.freeze,
          classification: Descriptor.new(
            version:      version,
            asset_class:  raw_class,
            claim:        raw_claim,
            subclass:     subclass,
            jurisdiction: jurisdiction,
            issuer_lei:   issuer_lei,
            attestation:  fields["rwa.attestation"],
            api_url:      api_url,
            unrecognized: unrecognized
          )
        )
      end

      def rwa_class?(value) = RWA_CLASSES.include?(value)
      def rwa_claim?(value) = RWA_CLAIMS.include?(value)

      def known_subclass?(asset_class, subclass)
        RWA_SUBCLASSES.fetch(asset_class, []).include?(subclass)
      end

      # ISO 17442: 20 alphanumerics whose mod-97-10 (ISO 7064) residue is 1.
      # Proves shape only - confirming the entity exists means asking GLEIF.
      def well_formed_lei?(lei)
        return false unless lei.is_a?(String) && LEI_RE.match?(lei)

        remainder = 0
        lei.each_char do |char|
          code = char.ord
          # Letters expand to two digits (A=10 .. Z=35) before folding in.
          digits = code >= 65 ? (code - 55).to_s : char
          digits.each_char { |d| remainder = ((remainder * 10) + (d.ord - 48)) % 97 }
        end
        remainder == 1
      end

      # ---- Layer 2 - attestation address derivation ----------------------

      # Attestation PDA, seeds ["attestation", credential, schema, nonce] off
      # the SAS program, with `nonce` fixed to the subject mint (draft §3.3).
      # That fixed nonce is what makes an attestation discoverable by
      # derivation instead of by indexer - and it works for legacy SPL mints
      # that cannot carry metadata at all.
      def attestation_pda(credential:, schema:, mint:, program_id: Config::SAS_PROGRAM_ID)
        derive(program_id, ["attestation", key_bytes(credential), key_bytes(schema), key_bytes(mint)])
      end

      # Schema PDA, seeds ["schema", credential, name, [version]].
      def schema_pda(credential:, name: "rwa.classification.v1", version: 1,
                     program_id: Config::SAS_PROGRAM_ID)
        derive(program_id, ["schema", key_bytes(credential), name, [version].pack("C")])
      end

      # Credential PDA, seeds ["credential", authority, name].
      def credential_pda(authority:, name:, program_id: Config::SAS_PROGRAM_ID)
        derive(program_id, ["credential", key_bytes(authority), name])
      end

      # ---- Layer 2 - account + payload decoding --------------------------

      # Decode a raw SAS `Attestation` account.
      #
      # Layout (sas-lib@1.0.10): u8 discriminator | nonce:[u8;32] |
      # credential:[u8;32] | schema:[u8;32] | data:(u32 len + bytes) |
      # signer:[u8;32] | expiry:i64 | token_account:[u8;32].
      #
      # Expiry comes from this account's native field, never from the payload
      # (draft §3.2) - carrying a second copy would create two sources of truth
      # with no rule for which wins, and only the native one is enforceable by
      # the program.
      #
      # @return [Hash] :nonce, :credential, :schema, :data, :signer, :expiry
      def decode_attestation_account(bytes)
        cur = Cursor.new(bytes.to_s.b, "attestation account")
        cur.take(1) # discriminator
        {
          nonce:      Addresses.encode_address(cur.take(32)),
          credential: Addresses.encode_address(cur.take(32)),
          schema:     Addresses.encode_address(cur.take(32)),
          data:       cur.take(U32_LE.decode(cur.take(4)).first),
          signer:     Addresses.encode_address(cur.take(32)),
          expiry:     I64_LE.decode(cur.take(8)).first
        }
      end

      # Decode a raw SAS `Schema` account far enough to read `is_paused`.
      #
      # `changeSchemaStatus` pauses every attestation under a schema at once,
      # and draft §3.4 says a paused schema MUST be treated as no better than
      # unattested - so this is a required input to {resolve_trust}.
      def decode_schema_account(bytes)
        cur = Cursor.new(bytes.to_s.b, "schema account")
        cur.take(1) # discriminator
        credential = Addresses.encode_address(cur.take(32))
        name        = cur.take(U32_LE.decode(cur.take(4)).first)
        description = cur.take(U32_LE.decode(cur.take(4)).first)
        layout      = cur.take(U32_LE.decode(cur.take(4)).first)
        field_names = cur.take(U32_LE.decode(cur.take(4)).first)

        {
          credential:  credential,
          name:        name.force_encoding(Encoding::UTF_8),
          description: description.force_encoding(Encoding::UTF_8),
          layout:      layout.bytes,
          field_names: field_names,
          is_paused:   cur.take(1).getbyte(0) != 0,
          version:     cur.take(1).getbyte(0)
        }
      end

      # Decode the `rwa.classification.v1` Borsh payload (draft §3.1).
      #
      # Nine positional fields, order normative - `layout` carries no names of
      # its own beyond the parallel `fieldNames` array, so a reordering here
      # silently mis-decodes rather than failing. Both `String` (code 12) and
      # `Vec<u8>` (code 13) are u32-length-prefixed on the wire, so a 32-byte
      # pubkey occupies 36 bytes.
      #
      # @return [Hash] pubkey fields base58-encoded, strings as UTF-8
      def decode_payload(bytes)
        cur = Cursor.new(bytes.to_s.b, "rwa.classification.v1 payload")

        mint             = cur.take_vec
        asset_class      = cur.take_string
        claim            = cur.take_string
        subclass         = cur.take_string
        jurisdiction     = cur.take_string
        issuer_lei       = cur.take_string
        property_commit  = cur.take_vec
        discovery_url    = cur.take_string
        discovery_signer = cur.take_vec

        {
          mint:             encode_key(mint, "mint"),
          class:            asset_class,
          claim:            claim,
          subclass:         subclass,
          jurisdiction:     jurisdiction,
          issuer_lei:       issuer_lei,
          # MAY be empty rather than zero-filled; prefer empty, since 32 zero
          # bytes is a valid-looking commitment to nothing (draft §3.1).
          property_commit:  property_commit.empty? ? nil : property_commit,
          discovery_url:    discovery_url,
          discovery_signer: discovery_signer.empty? ? nil : encode_key(discovery_signer, "discovery_signer")
        }
      end

      # Assemble an AttestationView from a decoded account + payload.
      #
      # @param schema_paused [Boolean] from {decode_schema_account}
      def build_attestation_view(address:, account:, payload:, schema_paused: false, revoked: false)
        AttestationView.new(
          address:          address.to_s,
          # Trust is keyed on the credential, the stable identity of the
          # attesting organisation - not on `signer`, which rotates freely via
          # changeAuthorizedSigners (draft §3.5).
          attester:         account.fetch(:credential),
          signer:           account.fetch(:signer),
          mint:             payload.fetch(:mint),
          asset_class:      presence(payload[:class]),
          claim:            presence(payload[:claim]),
          subclass:         presence(payload[:subclass]),
          jurisdiction:     presence(payload[:jurisdiction]),
          issuer_lei:       presence(payload[:issuer_lei]),
          property_commit:  payload[:property_commit],
          discovery_url:    presence(payload[:discovery_url]),
          discovery_signer: payload[:discovery_signer],
          expires_at:       account.fetch(:expiry),
          schema_paused:    schema_paused,
          revoked:          revoked
        )
      end

      # ---- Layer 2 - trust resolution ------------------------------------

      # Decide how far to trust a token's classification.
      #
      # Deliberately conservative: an attestation from an untrusted attester
      # carries no more weight than metadata the issuer wrote itself.
      #
      # @param mint [String] base58 mint being assessed. Required, not
      #   optional: an attestation naming a different mint must never confer
      #   trust here, and making the caller supply this is the only way to
      #   check that.
      # @param trusted_attesters [Array<String>] credentials this consumer
      #   honours. Caller-owned policy (draft §3.1); this gem ships no list.
      # @param mint_authorities [Array<String>] used to detect self-attestation.
      # @return [TrustAssessment]
      def resolve_trust(mint:, classification: nil, attestation: nil,
                        trusted_attesters: [], mint_authorities: [], now: nil)
        now ||= Time.now.to_i
        reasons = []

        if classification.nil? && attestation.nil?
          return TrustAssessment.new(
            level: :unknown, attester: nil, self_attested: false,
            conflicts: [].freeze,
            reasons: ["no classification metadata and no attestation"].freeze
          )
        end

        # A mint mismatch is categorically unlike the field disagreements
        # below. Those are two descriptions of the same subject diverging,
        # which the draft says to surface without picking a side. This is an
        # attestation that is not about this token at all, so it is discarded
        # outright rather than allowed to confer trust - otherwise any real
        # attestation, replayed against any mint, reads as verified. It is
        # still reported, because an attestation bound elsewhere is a louder
        # signal than no attestation at all.
        if attestation && attestation.mint != mint
          return TrustAssessment.new(
            level: classification ? :self_declared : :unknown,
            attester: nil, self_attested: false,
            conflicts: [%(mint: assessed "#{mint}" vs attestation "#{attestation.mint}")].freeze,
            reasons: ["attestation is bound to a different mint - disregarded"].freeze
          )
        end

        conflicts = (attestation && classification) ? find_conflicts(classification, attestation) : []
        reasons << "metadata disagrees with attestation" unless conflicts.empty?

        if attestation.nil?
          return TrustAssessment.new(
            level: :self_declared, attester: nil, self_attested: false,
            conflicts: conflicts.freeze,
            reasons: (reasons + ["no attestation referenced"]).freeze
          )
        end

        self_attested = attestation.self_attested?(mint_authorities)
        reasons << "attester is also a mint authority - not independent review" if self_attested

        downgrade = lambda do |reason|
          TrustAssessment.new(
            level: :self_declared, attester: attestation.attester,
            self_attested: self_attested, conflicts: conflicts.freeze,
            reasons: (reasons + [reason]).freeze
          )
        end

        # A paused schema is a kill switch over every attestation under it
        # (draft §3.4) - no better than unattested.
        return downgrade.call("schema is paused") if attestation.schema_paused
        return downgrade.call("attestation revoked") if attestation.revoked
        return downgrade.call("attester not in trust set") unless Array(trusted_attesters).include?(attestation.attester)

        if attestation.expired?(now)
          return TrustAssessment.new(
            level: :expired, attester: attestation.attester,
            self_attested: self_attested, conflicts: conflicts.freeze,
            reasons: (reasons + [
              "attestation expired at #{Time.at(attestation.expires_at).utc.iso8601}"
            ]).freeze
          )
        end

        TrustAssessment.new(
          level: :attested, attester: attestation.attester,
          self_attested: self_attested, conflicts: conflicts.freeze,
          reasons: (reasons + ["unexpired attestation from a trusted attester"]).freeze
        )
      end

      # ---- Layer 3 - discovery -------------------------------------------

      # Parse and structurally validate a `.well-known/rwa.json` document
      # (draft §4.2). Structure only - call {verify_discovery_document} before
      # trusting the contents.
      def parse_discovery_document(raw, mint:, now: nil)
        now ||= Time.now.to_i
        issues = []

        begin
          doc = JSON.parse(raw.to_s)
        rescue JSON::ParserError
          return DiscoveryResult.new(ok: false, document: nil,
                                     issues: ["discovery document is not valid JSON"].freeze)
        end

        unless doc.is_a?(Hash)
          return DiscoveryResult.new(ok: false, document: nil,
                                     issues: ["discovery document is not an object"].freeze)
        end

        unless doc["version"] == SUPPORTED_VERSION
          return DiscoveryResult.new(ok: false, document: nil,
                                     issues: [%(unsupported discovery version "#{doc["version"]}")].freeze)
        end

        # Binding the document to the mint stops a valid, correctly signed
        # document for one asset being replayed as the description of another.
        unless doc["mint"].is_a?(String) && doc["mint"] == mint
          return DiscoveryResult.new(ok: false, document: nil,
                                     issues: ["discovery document mint mismatch (expected #{mint})"].freeze)
        end

        # The draft's §4.2 example uses snake_case; the TypeScript reference
        # reads camelCase and has no test covering it, so the two disagree.
        # The spec wins as canonical, but both are accepted so documents the
        # reference already emitted still parse.
        issued_at_raw  = doc["issued_at"]  || doc["issuedAt"]
        expires_at_raw = doc["expires_at"] || doc["expiresAt"]

        unless issued_at_raw.is_a?(String) && expires_at_raw.is_a?(String)
          return DiscoveryResult.new(ok: false, document: nil,
                                     issues: ["missing issued_at/expires_at"].freeze)
        end

        expires_at = begin
          Time.parse(expires_at_raw).to_i
        rescue ArgumentError, TypeError
          nil
        end
        if expires_at.nil?
          return DiscoveryResult.new(ok: false, document: nil,
                                     issues: [%(unparseable expires_at "#{expires_at_raw}")].freeze)
        end
        issues << "discovery document expired at #{expires_at_raw}" if expires_at <= now

        endpoints = {}
        if doc["endpoints"].is_a?(Hash)
          doc["endpoints"].each do |name, url|
            unless url.is_a?(String) && url.start_with?("https://")
              issues << %(endpoint "#{name}" is not an https URL - dropped)
              next
            end
            endpoints[name] = url
          end
        end

        DiscoveryResult.new(
          ok: true, issues: issues.freeze,
          document: DiscoveryDocument.new(
            version:    doc["version"],
            mint:       doc["mint"],
            issued_at:  issued_at_raw,
            expires_at: expires_at_raw,
            manifest:   doc["manifest"].is_a?(String) ? doc["manifest"] : nil,
            endpoints:  endpoints.freeze
          )
        )
      end

      # Check the detached signature against the key the attestation authorized.
      #
      # Verifies the exact bytes as served - no canonicalization, per draft
      # §4.1, because every divergence between two JSON canonicalizers is a
      # bypass. TLS is not a substitute: it proves you reached the domain, not
      # who wrote the response. A lapsed domain can be re-registered with a
      # valid certificate; the attested signing key cannot.
      #
      # The verifier is injected so this module stays crypto-free. Pass a block
      # or any callable taking (message_bytes, signature_bytes, base58_pubkey);
      # {ed25519_verifier} is the batteries-included default.
      def verify_discovery_document(raw_bytes, signature, attestation, verifier = nil, &block)
        verifier ||= block || ed25519_verifier

        if attestation.discovery_signer.nil?
          return Verification.new(verified: false, reason: "attestation names no discovery signer")
        end

        ok = verifier.call(raw_bytes.to_s.b, signature.to_s.b, attestation.discovery_signer)
        Verification.new(
          verified: !!ok,
          reason: ok ? "signed by the attested discovery key"
                     : "signature does not match the attested discovery key"
        )
      rescue StandardError => e
        Verification.new(verified: false, reason: "verification threw: #{e.class}: #{e.message}")
      end

      # Default SignatureVerifier over RbNaCl, which the kit already depends on.
      def ed25519_verifier
        lambda do |message, signature, public_key_base58|
          require "rbnacl"
          key = RbNaCl::VerifyKey.new(key_bytes(public_key_base58))
          begin
            key.verify(signature, message)
          rescue RbNaCl::BadSignatureError
            false
          end
        end
      end

      # ---- Display --------------------------------------------------------

      # Badge text for a trust level. Per draft §5, `:expired` must never
      # collapse into `:unknown` - a lapsed issuer and an absent one are
      # different facts.
      def trust_label(level)
        case level
        when :attested      then "Verified"
        when :expired       then "Verification expired"
        when :self_declared then "Self-declared"
        when :unknown       then "Unidentified"
        else raise ArgumentError, "unknown trust level #{level.inspect}"
        end
      end

      # `Multifamily · Equity` - human-readable summary of the two enum axes.
      def describe(classification)
        asset = classification.subclass || classification.asset_class
        "#{titleize(asset)} · #{titleize(classification.claim)}"
      end

      private

      def failure(issues) = ParseResult.new(ok: false, classification: nil, issues: issues.freeze)

      def titleize(value)
        value.to_s.split("-").map { |word| word.sub(/\A./, &:upcase) }.join(" ")
      end

      def presence(value) = (value.nil? || value.empty?) ? nil : value

      def find_conflicts(classification, attestation)
        [
          ["class",        classification.asset_class,  attestation.asset_class],
          ["claim",        classification.claim,        attestation.claim],
          ["subclass",     classification.subclass,     attestation.subclass],
          ["jurisdiction", classification.jurisdiction, attestation.jurisdiction],
          ["issuer_lei",   classification.issuer_lei,   attestation.issuer_lei]
        ].filter_map do |field, meta, attested|
          next if meta.nil? || attested.nil? || meta == attested

          %(#{field}: metadata "#{meta}" vs attestation "#{attested}")
        end
      end

      def normalize_entries(entries)
        case entries
        when Hash then entries.to_a
        when nil  then []
        else
          entries.map do |entry|
            if entry.is_a?(Hash)
              [entry["key"] || entry[:key], entry["value"] || entry[:value]]
            else
              entry.to_a.first(2)
            end
          end
        end
      end

      def derive(program_id, seeds)
        Addresses.get_program_derived_address(
          program_address: Addresses.address(program_id.to_s), seeds: seeds
        ).address.to_s
      end

      def key_bytes(key) = Addresses.decode_address(Addresses.address(key.to_s))

      # Encoding attested bytes (rather than decoding the address they are
      # compared against) is normative - draft §3.1.
      def encode_key(bytes, field)
        unless bytes.bytesize == 32
          raise DecodeError, "#{field} is #{bytes.bytesize} bytes, expected 32"
        end

        Addresses.encode_address(bytes)
      end
    end

    # Bounds-checked positional reader. Borsh is positional and unframed, so a
    # short buffer otherwise yields nil slices that decode as plausible values.
    class Cursor
      def initialize(bytes, what)
        @bytes = bytes
        @what  = what
        @pos   = 0
      end

      def take(n)
        if n.negative? || @pos + n > @bytes.bytesize
          raise DecodeError, "#{@what} truncated: wanted #{n} bytes at offset #{@pos}, have #{@bytes.bytesize}"
        end

        slice = @bytes.byteslice(@pos, n)
        @pos += n
        slice
      end

      # Borsh `Vec<u8>`: u32 LE length prefix, then that many bytes.
      def take_vec = take(U32_LE.decode(take(4)).first)

      # Borsh `String`: identical wire shape, interpreted as UTF-8.
      def take_string = take_vec.force_encoding(Encoding::UTF_8)
    end

    # The impure half: fetch-and-decode against an RPC endpoint.
    #
    # Split out so every function above stays testable with zero network, and
    # so the read path is unmistakably separate from anything transactional.
    class Reader
      # @param rpc [Solana::Ruby::Kit::Rpc::Client]
      # @param commitment [Symbol, nil] commitment for the reads below; nil
      #   sends none and takes the endpoint's default. See
      #   Config::DEFAULT_COMMITMENT for why the default is not that.
      def initialize(rpc, program_id: Config::SAS_PROGRAM_ID,
                     commitment: Config::DEFAULT_COMMITMENT)
        @rpc = rpc
        @program_id = program_id
        @commitment = commitment
      end

      # Fetch the attestation a given credential has issued about `mint`.
      #
      # Derivation, not search: with a trust set in hand the caller already
      # knows each attester's credential, so this is one PDA derivation and one
      # account read per trusted attester - no indexer, no log scanning, and no
      # dependence on `rwa.attestation` being present or honest (draft §3.3).
      #
      # @return [AttestationView, nil] nil when no attestation exists. Note
      #   that a revoked attestation is byte-for-byte identical to one that
      #   never existed (draft §3.4) - absence is not evidence of revocation.
      def attestation_for(mint:, credential:, schema: nil, check_schema_pause: true)
        schema ||= Classification.schema_pda(credential: credential, program_id: @program_id)
        address = Classification.attestation_pda(
          credential: credential, schema: schema, mint: mint, program_id: @program_id
        )

        raw = fetch(address)
        return nil if raw.nil?

        account = Classification.decode_attestation_account(raw)
        payload = Classification.decode_payload(account.fetch(:data))

        paused = check_schema_pause ? schema_paused?(schema) : false

        Classification.build_attestation_view(
          address: address, account: account, payload: payload, schema_paused: paused
        )
      end

      # @return [Boolean] true if the schema is paused, or if it cannot be read
      #   - an unreadable kill switch is treated as thrown, not as absent.
      def schema_paused?(schema)
        raw = fetch(schema)
        return true if raw.nil?

        Classification.decode_schema_account(raw).fetch(:is_paused)
      end

      private

      # Same pinned shape as ExtraAccountMetas#fetch_account_data!.
      def fetch(address)
        options = { encoding: "base64" }
        options[:commitment] = @commitment if @commitment
        resp  = @rpc.get_account_info(Addresses.address(address.to_s).to_s, **options)
        value = resp.respond_to?(:value) ? resp.value : resp
        return nil if value.nil?

        encoded = value.respond_to?(:data) ? value.data : value["data"]
        b64, encoding = encoded.is_a?(Array) ? encoded : [encoded, "base64"]

        unless encoding.nil? || encoding == "base64"
          raise DecodeError, "account #{address} returned #{encoding.inspect}-encoded data, expected base64"
        end
        return nil if b64.nil?

        Base64.decode64(b64)
      end
    end
  end
end

require_relative "classification/issuance"
