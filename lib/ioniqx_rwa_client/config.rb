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
