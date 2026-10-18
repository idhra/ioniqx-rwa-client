# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "spec_helper"
require "json"
require "ioniqx_rwa_client/config"
require "ioniqx_rwa_client/eligibility"
require "ioniqx_rwa_client/hook_errors"

# Agreement between this gem's hand-written constants and the program's own IDL.
#
# Two things here were derived by hand — the `prove_eligibility` discriminator
# and the hook's error numbers — because the gem needed them before the IDL was
# committed. Both fail silently when wrong: a mismatched discriminator means the
# hook never finds the proof that was in the transaction all along, and a
# mismatched error number means a caller is handed an explanation for something
# that did not happen.
#
# The IDL is emitted by `anchor idl build` in ioniqx-rwa, so this is the program
# checking the client rather than the client checking itself.
#
# One IDL per released version of the hook, since every version is its own
# immutable program and a mint may be on any of them. A later version only
# appends instructions and errors, so the same constants must hold against each.
IDL_FILES = Dir[File.expand_path("../idl/ioniqx_transfer_restrictions_v*.json", __dir__)]
            .sort_by { |path| path[/_v(\d+)\.json\z/, 1].to_i }

RSpec.describe "IDL agreement" do
  let(:idls) { IDL_FILES.map { |path| JSON.parse(File.read(path)) } }

  it "carries an IDL for every program the gem addresses" do
    addresses = idls.map { |idl| idl["address"] }

    IoniqxRwa::Config::PROGRAM_IDS.each_value do |ids|
      expect(addresses).to include(ids[:transfer_restrictions]) if ids[:transfer_restrictions]
    end
  end

  # Localnet is what ioniqx-rwa builds now, so it is the newest version here.
  it "carries the current build as its newest version" do
    expect(idls.last["address"]).to eq(
      IoniqxRwa::Config.program_id(:transfer_restrictions, cluster: :localnet)
    )
  end

  IDL_FILES.each do |path|
    describe File.basename(path) do
      let(:idl) { JSON.parse(File.read(path)) }

      def instruction(name) = idl["instructions"].find { |i| i["name"] == name }

      # The hook scans the transaction comparing these eight bytes. Wrong, and every
      # gated transfer fails for want of a proof it was given.
      it "agrees with the program on the prove_eligibility discriminator" do
        expect(instruction("prove_eligibility")["discriminator"])
          .to eq(IoniqxRwa::Eligibility::PROVE_ELIGIBILITY.bytes)
      end

      # A proof is a Pubkey and a list of 32-byte siblings, in that order. The
      # encoder writes them positionally, so the order is the contract.
      it "agrees with the program on the proof arguments" do
        args = instruction("prove_eligibility")["args"]

        expect(args.map { |a| a["name"] }).to eq(%w[holder proof])
        expect(args.first["type"]).to eq("pubkey")
      end

      # An explanation for an error the program cannot raise sends a caller after
      # the wrong thing entirely.
      it "explains only errors the program actually defines" do
        defined = idl["errors"].to_h { |e| [ e["code"], e["name"] ] }

        IoniqxRwa::HookErrors::ERRORS.each do |code, (name, _action, _message)|
          expect(defined[code]).to eq(name.to_s),
                                   "#{code} is #{defined[code].inspect} in the IDL, not #{name}"
        end
      end

      # The reverse direction is a reminder, not a failure: the program defines
      # configuration-time errors a client can never hit, and those do not need
      # explanations. This pins the ones that *reach a transfer*.
      it "explains every error a transfer can fail with" do
        reachable = %w[
          PtpLimitExceeded EligibilityRootStale RedemptionWindowClosed
          RedemptionAmountExceeded EligibilityProofInvalid EligibilityProofMissing
          RedemptionDestinationNotTreasury NoRedemptionTreasury
        ]
        explained = IoniqxRwa::HookErrors::ERRORS.values.map { |(name, _, _)| name.to_s }

        expect(explained).to include(*reachable)
      end
    end
  end
end
