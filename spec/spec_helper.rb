# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "ioniqx_rwa_client"

# Shared shorthands. Defined once here rather than per spec file: a constant
# assigned inside an RSpec.describe block lands on Object, so two files each
# defining their own would silently overwrite one another.
Addresses = Solana::Ruby::Kit::Addresses
Codecs    = Solana::Ruby::Kit::Codecs

Dir[File.expand_path("support/**/*.rb", __dir__)].sort.each { |file| require file }

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
end
