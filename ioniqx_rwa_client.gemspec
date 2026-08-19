# frozen_string_literal: true

require_relative "lib/ioniqx_rwa_client/version"

Gem::Specification.new do |spec|
  spec.name                  = "ioniqx-rwa-client"
  spec.version               = IoniqxRwa::VERSION
  spec.authors               = ["Paul Zupan, Idhra Inc."]
  spec.summary               = "Ruby client for the ioniqx RWA on-chain programs"
  spec.description           = "Anchor instruction builders and a Token-2022 transfer-hook " \
                               "ExtraAccountMetaList resolver for the ioniqx RWA program suite, " \
                               "built on top of solana-ruby-kit."
  spec.homepage              = "https://github.com/pzupan/ioniqx-rwa-client"
  spec.license               = "Apache-2.0"
  spec.required_ruby_version = ">= 3.2.0"
  spec.require_paths         = ["lib"]

  spec.metadata = {
    "source_code_uri" => "#{spec.homepage}/tree/main",
    "bug_tracker_uri" => "#{spec.homepage}/issues"
  }

  spec.files = Dir["lib/**/*.rb", "idl/*.json"] +
               ["LICENSE", "NOTICE", "README.md", "ioniqx_rwa_client.gemspec"]
  spec.extra_rdoc_files = ["LICENSE", "NOTICE", "README.md"]

  # Pinned to a known-good series (BUILD.md §6). The kit supplies Codecs,
  # Addresses, Rpc::Client, Transactions - this gem must not reimplement them.
  #
  # Floored at 7.1.1.1: earlier releases left the Codecs helper surface private
  # and did not declare their own bigdecimal dependency, so the kit did not even
  # load on Ruby 3.4. Both are fixed there.
  spec.add_dependency "solana-ruby-kit", ">= 7.1.1.1", "< 8"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.13"
end
