# see: [NIST SP 800-38F, Section 6.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf)
module Rex; end
module Rex::Crypto; end
module Rex::Crypto::KeyWrap; end

module Rex::Crypto::KeyWrap::NIST_SP_800_38f
  def self.aes_unwrap_a2(kek, ciphertext)
    raise ArgumentError.new('kek must be 16, 24 or 32-bytes long') unless [16, 24, 32].include?(kek.length)
    icv1 = ("\xa6".b * 8)

    r = ciphertext.bytes.each_slice(8).map { |c| c.pack('C*') }
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

    return nil unless a == icv1

    r.join('')
  end
end