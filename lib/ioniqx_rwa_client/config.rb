# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

module IoniqxRwa
  # Program ids per cluster, and the commitment every read here uses.
  module Config
    CLUSTERS = %i[localnet devnet mainnet].freeze

    # Only where a program is actually deployed. An address listed for a
    # cluster that has none is worse than an absent one: a caller builds an
    # instruction to it, the runtime reports an account that does not exist,
    # and nothing in that failure says the program was never there.
    #
    # The transfer hook is live on devnet and is what the LiteSVM suite loads
    # on localnet. The other four ioniqx programs have addresses reserved in
    # ioniqx-rwa's Anchor.toml and are deployed nowhere, so they are not here.
    PROGRAM_IDS = {
      localnet: {
        transfer_restrictions: "2TYjyHt3XKoHJ7q217YLGiz1sCHYiLD64sioJqfQuWPK"
      },
      devnet: {
        transfer_restrictions: "2TYjyHt3XKoHJ7q217YLGiz1sCHYiLD64sioJqfQuWPK"
      },
      mainnet: {}
    }.freeze

    # The program id for a cluster, or nil where nothing is deployed.
    #
    # Nil rather than a raise: "not deployed on this cluster" is an ordinary
    # answer a caller can act on, and mainnet will keep giving it until there
    # is something true to say.
    def self.program_id(program, cluster:)
      PROGRAM_IDS.fetch(cluster.to_sym, {})[program.to_sym]
    end

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
