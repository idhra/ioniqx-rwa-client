# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

require "solana/ruby/kit"

require_relative "ioniqx_rwa_client/version"
require_relative "ioniqx_rwa_client/errors"
require_relative "ioniqx_rwa_client/config"
require_relative "ioniqx_rwa_client/extra_account_metas"
require_relative "ioniqx_rwa_client/transfer"
require_relative "ioniqx_rwa_client/classification"

# Ruby client for the ioniqx RWA on-chain programs.
#
# Layered ON TOP of solana-ruby-kit (BUILD.md §5.1): the kit owns transport,
# codecs, PDA derivation, transaction assembly and signing. This gem adds only
# the Anchor + Token-2022-transfer-hook + ioniqx-specific layer.
module IoniqxRwa
end
