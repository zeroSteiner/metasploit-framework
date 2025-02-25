require 'spec_helper'
require 'rex/crypto/key_wrap/nist_sp_800_38f'

RSpec.describe Rex::Crypto::KeyWrap::NIST_SP_800_38f do
  # Test vector from RFC 3394, Section 4.1 - 128-bit KEK
  let(:kek_128) { [ "000102030405060708090A0B0C0D0E0F" ].pack("H*") }
  let(:ciphertext_128) { [ "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5" ].pack("H*") }
  let(:expected_plaintext) { [ "00112233445566778899AABBCCDDEEFF" ].pack("H*") }

  # Test vector from RFC 3394, Section 4.2 - 192-bit KEK
  let(:kek_192) { [ "000102030405060708090A0B0C0D0E0F1011121314151617" ].pack("H*") }
  let(:ciphertext_192) { [ "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D" ].pack("H*") }

  # Test vector from RFC 3394, Section 4.3 - 256-bit KEK
  let(:kek_256) { [ "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" ].pack("H*") }
  let(:ciphertext_256) { [ "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7" ].pack("H*") }

  describe '.aes_unwrap' do
    it 'successfully unwraps a 128-bit key with a 128-bit KEK (RFC 3394, Section 4.1)' do
      unwrapped_key = described_class.aes_unwrap(kek_128, ciphertext_128)
      expect(unwrapped_key).to eq(expected_plaintext)
    end

    it 'successfully unwraps a 128-bit key with a 192-bit KEK (RFC 3394, Section 4.2)' do
      unwrapped_key = described_class.aes_unwrap(kek_192, ciphertext_192)
      expect(unwrapped_key).to eq(expected_plaintext)
    end

    it 'successfully unwraps a 128-bit key with a 256-bit KEK (RFC 3394, Section 4.3)' do
      unwrapped_key = described_class.aes_unwrap(kek_256, ciphertext_256)
      expect(unwrapped_key).to eq(expected_plaintext)
    end
  end
end
