# frozen_string_literal: true
# SPDX-License-Identifier: Apache-2.0

# The devnet reference deployment published in the draft's §3.6, created by the
# TypeScript reference (`npm run sas:devnet`) on sas-lib. Deriving these
# offline is what proves the Ruby seed order and encodings agree with the TS
# implementation without touching the network.
#
# Defined once here rather than per spec file: a constant assigned inside an
# RSpec.describe block lands on Object, so two files each defining their own
# would silently overwrite one another.
REF_CREDENTIAL  = "5Es4gSTWYemJxPMkWGYAi56Xzf2cSosJBRMaQaVVuxZq"
REF_SCHEMA      = "ASE1gwae1gBPZctkdNXdyGJcmqwPMVW9iMHqs22bJa9p"
REF_ATTESTATION = "G6qArVxuNwL9aC3EpTY443TfVTfyFmKwQhgmnd6rht9b"
REF_MINT        = "So11111111111111111111111111111111111111112"
