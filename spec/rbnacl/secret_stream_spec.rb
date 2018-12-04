# encoding: binary
# frozen_string_literal: true

RSpec.describe RbNaCl::SecretStream do
  let(:key) { vector :secret_key }

  let(:box) { RbNaCl::SecretStream.new(key) }
  let(:message) { StringIO.new(vector(:box_message)) }
  let(:ciphertext) { StringIO.new(message.read(64)) }
  let(:corrupt_ciphertext) { StringIO.new(message.read(64)) }

  context "new" do
    it "accepts strings" do
      expect { RbNaCl::SecretStream.new(key) }.to_not raise_error
    end

    it "raises on a nil key" do
      expect { RbNaCl::SecretStream.new(nil) }.to raise_error(TypeError)
    end

    it "raises on a short key" do
      expect { RbNaCl::SecretStream.new("hello") }.to raise_error RbNaCl::LengthError
    end
  end

  context "box" do
    it "roundtrips with block" do
      ciphertext = StringIO.new
      ciphertext.set_encoding("BINARY")
      box.box(message) do |chunk|
        ciphertext.write(chunk)
      end
      ciphertext.rewind

      plaintext = StringIO.new
      plaintext.set_encoding("BINARY")
      box.open(ciphertext) do |chunk|
        plaintext.write(chunk)
      end

      expect(plaintext.string).to eq message.string
    end

    it "raises on no block given" do
      expect do
        box.box(message)
      end.to raise_error(ArgumentError, "No block given")
    end
  end

  context "open" do
    it "raises on no block given" do
      expect do
        box.open(message)
      end.to raise_error(ArgumentError, "No block given")
    end

    it "raises on a truncated message to decrypt" do
      expect do
        box.open(ciphertext) do |chunk|
          # ...
        end
      end.to raise_error(RbNaCl::CryptoError, /Decryption failed. Ciphertext failed verification./)
    end

    it "raises on a corrupt ciphertext" do
      expect do
        box.open(corrupt_ciphertext) do |chunk|
          # ...
        end
      end.to raise_error(RbNaCl::CryptoError, /Decryption failed. Ciphertext failed verification./)
    end
  end
end
