# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

module IoniqxRwa
  # Program ids per cluster. Populated from `anchor keys list` once the
  # ioniqx-rwa workspace (BUILD.md §1-2) is built and deployed; devnet first.
  module Config
    CLUSTERS = %i[localnet devnet mainnet].freeze

    PROGRAM_IDS = {
      localnet: {},
      devnet:   {},
      mainnet:  {}
    }.freeze

    # Solana Attestation Service — used read-side by Classification (BUILD.md
    # §2.6 Layer 2). Same address on every cluster.
    SAS_PROGRAM_ID = "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG"

    # Commitment for every account read this gem makes.
    #
    # Solana's RPC default is `finalized` — roughly 32 slots, some 13 seconds,
    # behind the tip. Every read here is of an account the caller has just been
    # handed: the mint it is transferring, the validation account written when
    # that mint was configured. At `finalized` a mint issued moments ago is
    # simply absent, and what the caller gets is `account not found` for an
    # account that plainly exists — a failure that names nothing about
    # commitment and looks like a derivation bug.
    #
    # `confirmed` is what the ioniqx Rails app writes and reads at, so the two
    # sides agree on what exists. It is one supermajority vote deep: a
    # confirmed block is not guaranteed against rollback the way a finalized
    # one is, but the cost of being wrong here is a transaction that fails to
    # build, not a transfer that should not have happened.
    #
    # Pass `commitment: nil` to any of these classes to send none and take the
    # endpoint's own default.
    DEFAULT_COMMITMENT = :confirmed

    module_function

    # @param name [Symbol] :access_control, :transfer_restrictions, :tokenlock,
    #   :dividends, :title_compliance
    # @param cluster [Symbol]
    # @return [String] base58 program id
    def program_id(name, cluster: :devnet)
      ids = PROGRAM_IDS.fetch(cluster) { raise ArgumentError, "unknown cluster #{cluster.inspect}" }
      ids.fetch(name) do
        raise ArgumentError, "no program id for #{name.inspect} on #{cluster} - run `anchor keys list` and fill Config::PROGRAM_IDS"
      end
    end
  end
end
