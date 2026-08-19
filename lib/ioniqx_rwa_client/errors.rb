# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "solana/ruby/kit"

module IoniqxRwa
  # Base for every error this gem raises (BUILD.md §5.2).
  #
  # Subclasses the kit's SolanaError so callers already rescuing
  # Solana::Ruby::Kit::SolanaError catch these too. That parent takes a Symbol
  # `code` plus a context Hash — NOT a message string — and its constructor is
  # Sorbet-checked, so `raise SomeError, "text"` would otherwise die with a
  # TypeError before the intended error ever surfaced. This shim accepts the
  # ordinary Ruby message form while still populating `#code` and `#context`.
  class Error < Solana::Ruby::Kit::SolanaError
    # Overridden per subclass; surfaces on `#code` for programmatic rescue.
    def self.error_code = :IONIQX__ERROR

    def initialize(detail = nil, **context)
      @detail = detail&.to_s
      super(self.class.error_code, @detail ? context.merge(detail: @detail) : context)
    end

    # StandardError#message delegates to #to_s, so overriding #to_s alone keeps
    # both correct. Falls back to the kit's rendered code when built bare.
    def to_s = @detail || super
  end

  # Raised when an IDL is missing, malformed, or lacks a requested instruction.
  class IdlError < Error
    def self.error_code = :IONIQX__IDL_ERROR
  end

  # Raised when an instruction argument cannot be encoded for its IDL type.
  class EncodingError < Error
    def self.error_code = :IONIQX__ENCODING_ERROR
  end
end
