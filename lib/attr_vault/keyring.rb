module AttrVault
  class Key
    attr_reader :id, :value

    def initialize(id, value)
      if value.nil? || value.empty?
        raise InvalidKey, "key value required"
      end
      begin
        id = Integer(id)
      rescue
        raise InvalidKey, "key id must be an integer"
      end

      @id = id
      @value = value
    end

    def encrypt(message)
      Cryptor.encrypt(message, value)
    end

    def decrypt(ciphertext)
      Cryptor.decrypt(ciphertext, value)
    end

    def digest(data)
      # TODO: why does this use the base64 version of the key
      AttrVault::Encryption::hmac_digest(value, data)
    end

    def to_json(*args)
      { id: id, value: value }.to_json
    end
  end

  class MiscreantKey
    attr_reader :id

    def initialize(id, secret)
      @id = Integer(id)
      secret = Base64.strict_decode64(secret)
      @encryptor = Miscreant::AEAD.new("AES-SIV", secret)
      @cmac = Miscreant::AES::CMAC.new(secret)
    end

    def encrypt(message)
      return message if message.nil? || message.empty?

      nonce = Miscreant::AEAD.generate_nonce
      ciphertext = @encryptor.seal(message.encode(Encoding::BINARY), nonce: nonce)
      Sequel.blob(nonce + ciphertext)
    end

    def decrypt(encrypted)
      return encrypted if encrypted.nil? || encrypted.empty?

      nonce, ciphertext = encrypted[0...16], encrypted[16..-1]
      @encryptor.open(ciphertext, nonce: nonce)
    end

    def digest(data)
      @cmac.digest(data.encode(Encoding::BINARY))
    end

    def to_json(*args)
      { id: id, secret: secret }.to_json
    end
  end

  class LibSodiumKey
    attr_reader :id

    def initialize(id, secret)
      @id = Integer(id)
      binary_key = Base64.strict_decode64(secret)
      @secret_box = RbNaCl::SecretBox.new(binary_key)
      @authenticator = RbNaCl::HMAC::SHA256.new(binary_key)
    end

    def encrypt(message)
      return message if message.nil? || message.empty?

      nonce = RbNaCl::Random.random_bytes(@secret_box.nonce_bytes)
      ciphertext = @secret_box.encrypt(nonce, message)
      Sequel.blob(nonce + ciphertext)
    end

    def decrypt(encrypted)
      return encrypted if encrypted.nil? || encrypted.empty?

      nonce, ciphertext = encrypted[0...@secret_box.nonce_bytes], encrypted[@secret_box.nonce_bytes..-1]
      @secret_box.decrypt(nonce, ciphertext)
    end

    def digest(data)
      @authenticator.auth(data)
    end

    def to_json(*args)
      raise "this is scary"
      { id: id, secret: secret }.to_json
    end
  end

  class Keyring
    attr_reader :keys

    def self.load(keyring_data)
      keyring = Keyring.new
      begin
        candidate_keys = JSON.parse(keyring_data, symbolize_names: true)

        if candidate_keys.is_a?(Hash)
          candidate_keys.each do |key_id, key|
            if key.is_a?(Hash)
              case key[:type]
              when 'fernet'
                keyring.add_key(Key.new(key_id.to_s, key[:secret]))
              when 'miscreant'
                require 'miscreant'
                keyring.add_key(MiscreantKey.new(key_id.to_s, key[:secret]))
              when 'libsodium'
                require 'rbnacl'
                keyring.add_key(LibSodiumKey.new(key_id.to_s, key[:secret]))
              else
                raise InvalidKeyring, "Invalid key type: #{key_id.inspect}"
              end
            else
              keyring.add_key(Key.new(key_id.to_s, key))
            end
          end
        else
          raise InvalidKeyring, "Invalid JSON structure"
        end
      rescue StandardError => e
        raise InvalidKeyring, e.message
      end
      keyring
    end

    def initialize
      @keys = []
    end

    def add_key(k)
      @keys << k
    end

    def drop_key(id_or_key)
      id = if id_or_key.is_a? Key
             id_or_key.id
           else
             id_or_key
           end
      @keys.reject! { |k| k.id == id }
    end

    def fetch(id)
      @keys.find { |k| k.id == id } or raise UnknownKey, id
    end

    def has_key?(id)
      !@keys.find { |k| k.id == id }.nil?
    end

    def current_key
      k = @keys.sort_by(&:id).last
      if k.nil?
        raise KeyringEmpty, "No keys in keyring"
      end
      k
    end

    def digests(data)
      keys.map { |k| k.digest(data) }
    end

    def to_json
      @keys.each_with_object({}) do |k,obj|
        obj[k.id] = k.value
      end.to_json
    end
  end
end
