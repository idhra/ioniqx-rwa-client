# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"
require "ioniqx_rwa_client/hook_errors"

# A rejected transfer surfaces as `custom program error: 0x179b` and nothing
# else. The caller is a wallet or a venue with no view of the offering's policy,
# so the number is the whole of what they have.
RSpec.describe IoniqxRwa::HookErrors do
  # The single most likely failure for anyone integrating after the roster gate
  # landed: they built a TransferChecked the way they always have.
  it "explains a missing eligibility proof and says what to do about it" do
    explained = described_class.explain(6043)

    expect(explained.name).to eq(:EligibilityProofMissing)
    expect(explained.action).to eq(:fix)
    expect(explained.message).to match(/Prepend IoniqxRwa::Eligibility.prove/)
  end

  # These two are the ones worth getting right: both are usually transient and
  # neither is the caller's fault, which no error code can convey.
  it "marks a stale root as not the caller's problem to solve" do
    explained = described_class.explain(6038)

    expect(explained).to be_retryable
    expect(explained.message).to match(/not just yours/)
    expect(explained.message).to match(/wait for the issuer/)
  end

  it "tells a caller with a rejected proof to fetch a fresh one" do
    explained = described_class.explain(6041)

    expect(explained).to be_retryable
    expect(explained.message).to match(/republished after the proof was fetched/)
  end

  # Resending will not help, and saying so is the useful part.
  it "marks an exhausted transfer cap as refused rather than retryable" do
    expect(described_class.explain(6034).action).to eq(:refused)
    expect(described_class.explain(6039).action).to eq(:refused)
  end

  describe ".explain" do
    it "reads the hex form a validator log prints" do
      expect(described_class.explain("0x179b").name).to eq(:EligibilityProofMissing)
    end

    # Inventing an explanation for another program's error is worse than none:
    # the caller would chase the wrong program.
    it "returns nil for a code this program does not define" do
      expect(described_class.explain(1)).to be_nil
      expect(described_class.explain(6999)).to be_nil
    end
  end

  describe ".explain_log" do
    it "pulls the code out of a validator log line" do
      log = "Program 2TYjy... failed: custom program error: 0x179b"

      expect(described_class.explain_log(log).name).to eq(:EligibilityProofMissing)
    end

    it "pulls the code out of an RPC InstructionError" do
      expect(described_class.explain_log("InstructionError(0, Custom(6038))").name)
        .to eq(:EligibilityRootStale)
    end

    it "returns nil for text carrying no program error" do
      expect(described_class.explain_log("blockhash not found")).to be_nil
    end
  end
end
