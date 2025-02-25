# see: [NIST SP 800-38F, Section 6.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf)
module Rex; end
module Rex::Crypto; end
module Rex::Crypto::KeyWrap; end

module Rex::Crypto::KeyWrap::NIST_SP_800_38f

  # Performs AES key unwrapping from NIST SP 800-38F.
  #
  # @param kek [String] The key-encryption key (KEK) used to unwrap the ciphertext.
  # @param key_data [String] The wrapped key data.
  # @param authenticated [Boolean] Whether to check the data integrity or not.
  # @return [String, nil] The unwrapped key on success, or nil if unwrapping fails.
  #
  # @see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
  def self.aes_unwrap(kek, key_data, authenticated: true)
    # padded mode as described in Section 6.3 is not supported at this time
    raise ArgumentError.new('kek must be 16, 24 or 32-bytes long') unless [16, 24, 32].include?(kek.length)
    icv1 = ("\xa6".b * 8)

    r = key_data.bytes.each_slice(8).map { |c| c.pack('C*') }
    a = r.shift

    ciph = -> (data) do
      # per-section 5.1, AES is the only suitable block cipher
      cipher = OpenSSL::Cipher::AES.new(kek.length * 8, :ECB).decrypt
      cipher.key = kek
      cipher.padding = 0
      cipher.update(data)
    end

    n = r.length

    5.downto(0) do |j|
      (n - 1).downto(0) do |i|
        atr = [a.unpack1('Q>') ^ ((n * j) + i + 1)].pack('Q>') + r[i]

        b = ciph.call(atr)
        a = b[...8]
        r[i] = b[-8...]
      end
    end

    # setting authenticated to true effectively switches the operation from Section 6.2 algorithm #2 to algorithm #4
    if authenticated && a != icv1
      raise Rex::RuntimeError.new('ICV1 integrity check failed in KW-AD(C)')
    end

    r.join('')
  end
end