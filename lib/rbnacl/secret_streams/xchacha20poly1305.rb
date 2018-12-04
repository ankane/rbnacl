# encoding: binary
# frozen_string_literal: true

module RbNaCl
  module SecretStreams
    # The SecretStream class boxes and unboxes messages
    #
    # This class uses the given secret key to encrypt and decrypt messages.
    class XChaCha20Poly1305
      extend Sodium
      if Sodium::Version.supported_version?("1.0.14")
        sodium_type :secretstream
        sodium_primitive :xchacha20poly1305
        sodium_constant :ABYTES
        sodium_constant :HEADERBYTES
        sodium_constant :KEYBYTES
        sodium_constant :MESSAGEBYTES_MAX
        sodium_constant :TAG_MESSAGE
        sodium_constant :TAG_PUSH
        sodium_constant :TAG_REKEY
        sodium_constant :TAG_FINAL

        sodium_function :secretstream_xchacha20poly1305_init_push,
                        :crypto_secretstream_xchacha20poly1305_init_push,
                        %i[pointer pointer pointer]

        sodium_function :secretstream_xchacha20poly1305_push,
                        :crypto_secretstream_xchacha20poly1305_push,
                        %i[pointer pointer pointer pointer ulong_long pointer ulong_long uchar]

        sodium_function :secretstream_xchacha20poly1305_init_pull,
                        :crypto_secretstream_xchacha20poly1305_init_pull,
                        %i[pointer pointer pointer]

        sodium_function :secretstream_xchacha20poly1305_pull,
                        :crypto_secretstream_xchacha20poly1305_pull,
                        %i[pointer pointer pointer pointer pointer ulong_long pointer ulong_long]

        CHUNK_SIZE = 4096

        # Create a new SecretStream
        #
        # Sets up the Box with a secret key fro encrypting and decrypting messages.
        #
        # @param key [String] The key to encrypt and decrypt with
        #
        # @raise [RbNaCl::LengthError] on invalid keys
        #
        # @return [RbNaCl::SecretBox] The new Box, ready to use
        def initialize(key)
          @key = Util.check_string(key, KEYBYTES, "Secret key")
        end

        # Encrypts a message
        #
        # Encrypts the message with the key set up when
        # initializing the class.
        #
        # @param message [String] The message to be encrypted.
        #
        # @raise [ArgumentError] If no block is given
        #
        # @return [String] The ciphertext without the nonce prepended (BINARY encoded)
        def box(io)
          raise ArgumentError, "No block given" unless block_given?

          io = check_io(io)
          buf_out = Util.zeros(CHUNK_SIZE + ABYTES)
          header = Util.zeros(HEADERBYTES)
          state = State.new

          self.class.secretstream_xchacha20poly1305_init_push(state, header, @key)

          yield header

          each_chunk(io, CHUNK_SIZE) do |chunk|
            tag = io.eof? ? TAG_FINAL : 0

            self.class.secretstream_xchacha20poly1305_push(state, buf_out, nil, chunk, chunk.bytesize, nil, 0, tag)

            yield buf_out[0, chunk.bytesize + ABYTES]
          end

          nil
        end
        alias encrypt box

        # Decrypts a ciphertext
        #
        # Decrypts the ciphertext using the key setup when
        # initializing the class.
        #
        # @param ciphertext [String] The message to be decrypted.
        #
        # @raise [ArgumentError] If no block is given
        # @raise [RbNaCl::CryptoError] If the ciphertext cannot be authenticated.
        #
        # @return [String] The decrypted message (BINARY encoded)
        def open(io)
          raise ArgumentError, "No block given" unless block_given?

          io = check_io(io)
          buf_out = Util.zeros(CHUNK_SIZE)
          state = State.new
          tag = Util.zeros(1)

          check_header(state, io)

          each_chunk(io, CHUNK_SIZE + ABYTES) do |chunk|
            success = self.class.secretstream_xchacha20poly1305_pull(state, buf_out, nil, tag, chunk,
                                                                     chunk.bytesize, nil, 0)
            fail_decryption unless success

            check_tag(tag) if io.eof?

            yield buf_out[0, chunk.bytesize - ABYTES]
          end

          nil
        end
        alias decrypt open

        # The crypto primitive for the SecretStream instance
        #
        # @return [Symbol] The primitive used
        def primitive
          self.class.primitive
        end

        # The key bytes for the SecretStream class
        #
        # @return [Integer] The number of bytes in a valid key
        def self.key_bytes
          KEYBYTES
        end

        # The key bytes for the SecretStream instance
        #
        # @return [Integer] The number of bytes in a valid key
        def key_bytes
          KEYBYTES
        end

        private

        def check_header(state, io)
          header = io.read(HEADERBYTES)
          fail_decryption unless header && header.bytesize == HEADERBYTES

          success = self.class.secretstream_xchacha20poly1305_init_pull(state, header, @key)
          fail_decryption unless success
        end

        def check_tag(tag)
          # returned as char instead of int
          tag = tag.unpack("C").first
          fail_decryption if tag != TAG_FINAL
        end

        def check_io(io)
          io = StringIO.new(io) if io.is_a?(String)
          io
        end

        def fail_decryption
          raise CryptoError, "Decryption failed. Ciphertext failed verification."
        end

        # prefer this over IO#each_line so don't have to worry about encoding
        def each_chunk(io, chunk_size)
          loop do
            yield io.read(chunk_size)
            break if io.eof?
          end
        end

        # ref: jedisct1/libsodium/src/libsodium/include/sodium/crypto_secretstream_xchacha20poly1305.h#L56
        class State < FFI::Struct
          layout :k, [:uchar, RbNaCl::Streams::ChaCha20IETF::KEYBYTES],
                 :nonce, [:uchar, RbNaCl::Streams::ChaCha20IETF::NONCEBYTES],
                 :_pad, [:uchar, 8]
        end
      end
    end
  end
end
