# encoding: binary
# frozen_string_literal: true

module RbNaCl
  module Streams
    # This class contains wrappers for the IETF implementation of
    # Authenticated Encryption with Additional Data using ChaCha20-Poly1305
    class ChaCha20IETF
      extend Sodium

      sodium_type :stream
      sodium_primitive :chacha20_ietf
      sodium_constant :KEYBYTES
      sodium_constant :NONCEBYTES
    end
  end
end
