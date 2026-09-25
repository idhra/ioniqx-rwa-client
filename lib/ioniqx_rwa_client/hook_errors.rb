# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

module IoniqxRwa
  # Turns the transfer hook's custom program errors into sentences.
  #
  # A rejected transfer surfaces as `custom program error: 0x179b` and nothing
  # else. The caller is a wallet or a venue with no view of the offering's
  # policy, so the number is the whole of what they have — and several of these
  # failures are transient and not the caller's fault at all, which is
  # impossible to guess from a code.
  #
  # Anchor numbers custom errors from 6000 in declaration order. These are the
  # ones a *client* can actually hit; the configuration-time errors (a policy
  # that could never admit anyone, an incoherent structure) are the issuer's
  # problem and never reach a transfer.
  module HookErrors
    # Whether the caller can do anything about it, which is the part a code
    # cannot convey:
    #
    #   :fix     — the transaction was built wrong. Change it and resend.
    #   :retry   — transient. The state moved under you; re-read and resend.
    #   :refused — the offering says no. Resending will not help.
    ERRORS = {
      6034 => [ :PtpLimitExceeded, :refused,
                "This offering caps how much can change hands per period (§7704) and that " \
                "cap is exhausted for the current window. It resets when the window rolls over." ],
      6035 => [ :PtpCounterMismatch, :fix,
                "The §7704 counter account is not the one derived for this mint. Resolve the " \
                "hook's accounts from the mint's validation account rather than supplying them." ],
      6038 => [ :EligibilityRootStale, :retry,
                "The offering's eligible-holder set has not been republished inside its freshness " \
                "bound, so the hook is refusing every transfer of this mint — not just yours. " \
                "Nothing you send makes it younger; wait for the issuer to republish." ],
      6039 => [ :RedemptionWindowClosed, :refused,
                "This is a redemption and its settlement date has not arrived. Redemption is gated " \
                "to a notice period plus the offering's accounting cycle." ],
      6040 => [ :RedemptionAmountExceeded, :refused,
                "The redemption is larger than the notice the holder gave." ],
      6041 => [ :EligibilityProofInvalid, :retry,
                "The eligibility proof does not reproduce this offering's current root. Usually the " \
                "root was republished after the proof was fetched — fetch a fresh proof and resend." ],
      6042 => [ :EligibilityProofTooLong, :fix,
                "The eligibility proof is longer than the program will verify." ],
      6043 => [ :EligibilityProofMissing, :fix,
                "This offering gates transfers on an eligible-holder set and no proof was attached. " \
                "Prepend IoniqxRwa::Eligibility.prove for the recipient — and for the sender too if " \
                "the offering is two-sided." ],
      6044 => [ :RedemptionMarkerMismatch, :fix,
                "The redemption marker account is not the one derived for this mint and holder." ],
      # The sender has given redemption notice and its window is open, so the
      # hook treats every transfer out of that wallet as the redemption leg.
      # Hit by any ordinary trade from the wallet, not only by a malformed
      # redemption — which is why the message says when it ends.
      6045 => [ :RedemptionDestinationNotTreasury, :refused,
                "The sender has a redemption notice in progress for this offering, and until it " \
                "settles or lapses every transfer out of that wallet must go to the offering's " \
                "redemption treasury. Complete the redemption, or wait for the notice to end." ],
      6046 => [ :NoRedemptionTreasury, :refused,
                "The sender has a redemption notice in progress, but this offering has no " \
                "redemption treasury configured, so no redemption can settle. Only the issuer " \
                "can fix this." ]
    }.freeze

    Explanation = Struct.new(:code, :name, :action, :message, keyword_init: true) do
      def retryable? = action == :retry
      def to_s = "#{name} (#{code}): #{message}"
    end

    module_function

    # @param code [Integer, String] the custom program error number, decimal or
    #   the `0x...` form a validator log prints.
    # @return [Explanation, nil] nil for a code this program does not define,
    #   which is the honest answer — inventing an explanation for someone
    #   else's error is worse than none.
    def explain(code)
      number = code.is_a?(String) ? Integer(code, 16) : code.to_i
      name, action, message = ERRORS[number]
      return nil if name.nil?

      Explanation.new(code: number, name: name, action: action, message: message)
    end

    # Pulls the custom error number out of a validator log line or an RPC error
    # string, if there is one.
    def explain_log(text)
      match = text.to_s.match(/custom program error:\s*(0x\h+)/i) ||
              text.to_s.match(/Custom\((\d+)\)/)
      return nil if match.nil?

      explain(match[1].start_with?("0x") ? match[1] : match[1].to_i)
    end
  end
end
