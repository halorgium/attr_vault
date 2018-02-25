require 'spec_helper'
require 'json'

describe AttrVault do
  let(:key_ids) { [ 1, 2, 3, 4 ] }
  let(:key_values) do
    [ 'aFJDXs+798G7wgS/nap21LXIpm/Rrr39jIVo2m/cdj8=',
      'hUL1orBBRckZOuSuptRXYMV9lx5Qp54zwFUVwpwTpdk=',
      {type: 'fernet', secret: 'LJj3qWvvRJ4A86/rCzLTNt5xYZfszh9gonHrostX6dc='},
      {type: 'miscreant', secret: 'L82PBeHUJuEiDmmnh1joCTHDLUDBzPjlwAiJmPz63HU='} ]
  end

  def make_keyring(desired_key_ids)
    Hash[key_ids.zip(key_values).select {|k,v| desired_key_ids.include?(k)}]
  end

  let(:key1_id) { key_ids.fetch(0) }
  let(:key1) { keyring[key1_id] }

  let(:key2_id) { key_ids.fetch(1) }
  let(:key2) { keyring[key2_id] }

  let(:key3_id) { key_ids.fetch(2) }
  let(:key3) { keyring[key3_id] }

  let(:key4_id) { key_ids.fetch(3) }
  let(:key4) { keyring[key4_id] }

  let(:key_id)  { key3_id }
  let(:key) { key3 }

  let(:old_keyring) do
    make_keyring([key_id])
  end
  let(:new_keyring) do
    make_keyring(key_ids)
  end
  let(:keyring) { old_keyring }

  context "with a single encrypted column" do
    let(:item) do
      k = keyring.to_json
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret
      end
    end

    context "with a new object" do
      it "does not affect other attributes" do
        not_secret = 'jimi hendrix was rather talented'
        s = item.create(not_secret: not_secret)
        s.reload
        expect(s.not_secret).to eq(not_secret)
        expect(s.this.where(not_secret: not_secret).count).to eq 1
      end

      it "encrypts non-empty values" do
        secret = 'lady gaga? also rather talented'
        s = item.create(secret: secret)
        s.reload
        expect(s.secret).to eq(secret)
        s.columns.each do |col|
          expect(s.this.where(Sequel.cast(Sequel.cast(col, :text), :bytea) => secret).count).to eq 0
        end
      end

      it "stores empty values as empty" do
        secret = ''
        s = item.create(secret: secret)
        s.reload
        expect(s.secret).to eq('')
        expect(s.secret_encrypted).to eq('')
      end

      it "stores nil values as nil" do
        s = item.create(secret: nil)
        s.reload
        expect(s.secret).to be_nil
        expect(s.secret_encrypted).to be_nil
      end

      it "sets fields to empty that were previously not empty" do
        s = item.create(secret: 'joyce hatto')
        s.reload
        s.update(secret: '')
        s.reload
        expect(s.secret).to eq ''
        expect(s.secret_encrypted).not_to be_nil
      end

      it "avoids updating existing values when those do not change" do
        the_secret = "I'm not saying it was aliens..."
        s = item.create(secret: the_secret)
        s.reload
        s.secret = the_secret
        expect(s.save_changes).to be_nil
      end

      it "stores the key id" do
        secret = 'it was professor plum with the wrench in the library'
        s = item.create(secret: secret)
        s.reload
        expect(s.key_id).to eq(key_id)
      end
    end

    context "with an existing object" do
      it "does not affect other attributes" do
        not_secret = 'soylent is not especially tasty'
        s = item.create
        s.update(not_secret: not_secret)
        s.reload
        expect(s.not_secret).to eq(not_secret)
        expect(s.this.where(not_secret: not_secret).count).to eq 1
      end

      it "encrypts non-empty values" do
        secret = 'soylent green is made of people'
        s = item.create
        s.update(secret: secret)
        s.reload
        expect(s.secret).to eq(secret)
        s.columns.each do |col|
          expect(s.this.where(Sequel.cast(Sequel.cast(col, :text), :bytea) => secret).count).to eq 0
        end
      end

      it "stores empty values as empty" do
        s = item.create(secret: "darth vader is luke's father")
        s.update(secret: '')
        s.reload
        expect(s.secret).to eq('')
        expect(s.secret_encrypted).to eq('')
      end

      it "leaves nil values as nil" do
        s = item.create(secret: "dr. crowe was dead all along")
        s.update(secret: nil)
        s.reload
        expect(s.secret).to be_nil
        expect(s.secret_encrypted).to be_nil
      end

      it "stores the key id" do
        secret = 'animal style'
        s = item.create
        s.update(secret: secret)
        s.reload
        expect(s.key_id).to eq(key_id)
      end

      it "reads a never-set encrypted field as nil" do
        s = item.create
        expect(s.secret).to be_nil
      end

      it "avoids updating existing values when those do not change" do
        the_secret = "Satoshi Nakamoto"
        s = item.create
        s.update(secret: the_secret)
        s.secret = the_secret
        expect(s.save_changes).to be_nil
      end

      it "reads the correct value for a dirty field before the object is saved" do
        s = item.create
        secret = 'mcmurphy is lobotomized =('
        s.secret = secret
        expect(s.secret).to eq secret
      end
    end
  end

  context "with multiple encrypted columns" do
    let(:key_data) do
      make_keyring([key1_id])
    end
    let(:item) do
      k = key_data.to_json
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret
        vault_attr :other
      end
    end

    it "does not clobber other attributes" do
      secret1 = "superman is really mild-mannered reporter clark kent"
      secret2 = "batman is really millionaire playboy bruce wayne"
      s = item.create(secret: secret1)
      s.reload
      expect(s.secret).to eq secret1
      s.update(other: secret2)
      s.reload
      expect(s.secret).to eq secret1
      expect(s.other).to eq secret2
    end
  end

  context "with items encrypted with an older key" do
    let(:key1) do
      make_keyring([key1_id])
    end
    let(:key2) do
      make_keyring([key2_id])
    end
    let(:partial_keyring) { key1.to_json }
    let(:full_keyring)    { key1.merge(key2).to_json }
    let(:item1) do
      k = partial_keyring
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret
        vault_attr :other
      end
    end
    let(:item2) do
      k = full_keyring
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret
        vault_attr :other
      end
    end

    it "rewrites the items using the current key" do
      secret1 = 'mrs. doubtfire is really a man'
      secret2 = 'tootsie? also a man'
      record = item1.create(secret: secret1)
      expect(record.key_id).to eq key1_id
      expect(record.secret).to eq secret1

      old_secret_encrypted = record.secret_encrypted

      new_key_record = item2[record.id]
      new_key_record.update(secret: secret2)
      new_key_record.reload

      expect(new_key_record.key_id).to eq key2_id
      expect(new_key_record.secret).to eq secret2
      expect(new_key_record.secret_encrypted).not_to eq old_secret_encrypted
    end

    it "rewrites the items using the current key even if they are not updated" do
      secret1 = 'the planet of the apes is really earth'
      secret2 = 'the answer is 42'
      record = item1.create(secret: secret1)
      expect(record.key_id).to eq key1_id
      expect(record.secret).to eq secret1

      old_secret_encrypted = record.secret_encrypted

      new_key_record = item2[record.id]
      new_key_record.update(other: secret2)
      new_key_record.reload

      expect(new_key_record.key_id).to eq key2_id
      expect(new_key_record.secret).to eq secret1
      expect(new_key_record.secret_encrypted).not_to eq old_secret_encrypted
      expect(new_key_record.other).to eq secret2
    end
  end

  context "with plaintext source fields" do
    let(:key_id)   { 1 }
    let(:key_data) do
      { key_id => 'aFJDXs+798G7wgS/nap21LXIpm/Rrr39jIVo2m/cdj8=' }.to_json
    end
    let(:item1) do
      k = key_data
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret
        vault_attr :other
      end
    end
    let(:item2) do
      k = key_data
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret, migrate_from_field: :not_secret
        vault_attr :other, migrate_from_field: :other_not_secret
      end
    end

    it "copies a plaintext field to an encrypted field when saving the object" do
      becomes_secret = 'the location of the lost continent of atlantis'
      s = item1.create(not_secret: becomes_secret)
      reloaded = item2[s.id]
      expect(reloaded.not_secret).to eq becomes_secret
      reloaded.save
      reloaded.reload
      expect(reloaded.not_secret).to be_nil
      expect(reloaded.secret).to eq becomes_secret
    end

    it "supports converting multiple fields" do
      becomes_secret1 = 'the location of the fountain of youth'
      becomes_secret2 = 'the location of the lost city of el dorado'
      s = item1.create(not_secret: becomes_secret1, other_not_secret: becomes_secret2)
      reloaded = item2[s.id]
      expect(reloaded.not_secret).to eq becomes_secret1
      expect(reloaded.other_not_secret).to eq becomes_secret2
      reloaded.save
      reloaded.reload
      expect(reloaded.not_secret).to be_nil
      expect(reloaded.secret).to eq becomes_secret1
      expect(reloaded.other_not_secret).to be_nil
      expect(reloaded.other).to eq becomes_secret2
    end

    it "nils out the plaintext field and persists the encrypted field on save" do
      becomes_secret = 'the location of all those socks that disappear from the dryer'
      new_secret = 'the location of pliny the younger drafts'
      s = item1.create(not_secret: becomes_secret)
      reloaded = item2[s.id]
      expect(reloaded.secret).to eq(becomes_secret)
      reloaded.secret = new_secret
      expect(reloaded.secret).to eq(new_secret)
      reloaded.save
      expect(reloaded.secret).to eq(new_secret)
      expect(reloaded.not_secret).to be_nil
    end
  end

  context "with renamed database fields" do
    let(:key_data) do
     { '1' => 'aFJDXs+798G7wgS/nap21LXIpm/Rrr39jIVo2m/cdj8=' }.to_json
    end

    it "supports renaming the encrypted field" do
      k = key_data
      item = Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :classified_info,
                   encrypted_field: :secret_encrypted
      end

      secret = "we've secretly replaced the fine coffee they usually serve with Folgers Crystals"
      s = item.create(classified_info: secret)
      s.reload
      expect(s.classified_info).to eq secret
      expect(s.secret_encrypted).not_to eq secret
    end

    it "supports renaming the key id field" do
      k = key_data
      item = Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k, key_field: :alt_key_id
        vault_attr :secret
      end

      secret = "up up down down left right left right b a"
      s = item.create(secret: secret)
      s.reload
      expect(s.secret).to eq secret
      expect(s.secret_encrypted).not_to eq secret
      expect(s.alt_key_id).not_to be_nil
      expect(s.key_id).to be_nil
    end
  end

  context "with a digest field" do
    let(:key_id)   { 1 }
    let(:key) do
      { key_id => 'aFJDXs+798G7wgS/nap21LXIpm/Rrr39jIVo2m/cdj8=' }
    end
    let(:item) do
      k = key.to_json
      Class.new(Sequel::Model(:items)) do
        include AttrVault
        vault_keyring k
        vault_attr :secret, digest_field: :secret_digest
        vault_attr :other, digest_field: :other_digest
      end
    end

    def test_digest(key, data)
      OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'),
                           key[key_id], data)
    end

    def count_matching_digests(item_class, digest_field, secret)
      item.where({digest_field => item_class.vault_digests(secret)}).count
    end

    it "records the hmac of the plaintext value" do
      secret = 'snape kills dumbledore'
      s = item.create(secret: secret)
      expect(s.secret_digest).to eq(test_digest(key, secret))
      expect(count_matching_digests(item, :secret_digest, secret)).to eq(1)
    end

    it "can record multiple digest fields" do
      secret = 'joffrey kills ned'
      other_secret = '"gomer pyle" lawrence kills himself'
      s = item.create(secret: secret, other: other_secret)
      expect(s.secret_digest).to eq(test_digest(key, secret))
      expect(s.other_digest).to eq(test_digest(key, other_secret))

      # Check vault_digests feature matching against the database.
      expect(count_matching_digests(item, :secret_digest, secret)).to eq(1)
      expect(count_matching_digests(item, :other_digest, other_secret)).to eq(1)

      # Negative tests for mismatched digesting.
      expect(count_matching_digests(item, :secret_digest, other_secret))
        .to eq(0)
      expect(count_matching_digests(item, :other_digest, secret)).to eq(0)
    end

    it "records the digest for an empty field" do
      s = item.create(secret: '', other: '')
      expect(s.secret_digest).to eq(test_digest(key, ''))
      expect(s.other_digest).to eq(test_digest(key, ''))
    end

    it "records the digest of a nil field" do
      s = item.create
      expect(s.secret_digest).to be_nil
      expect(s.other_digest).to be_nil
    end
  end
end

describe "stress test" do
  let(:key_id)   { 1 }
  let(:key_data) do
    data = [ {type: 'fernet', secret: 'LJj3qWvvRJ4A86/rCzLTNt5xYZfszh9gonHrostX6dc='},
             {type: 'miscreant', secret: 'L82PBeHUJuEiDmmnh1joCTHDLUDBzPjlwAiJmPz63HU='} ].first
    { key_id => data }.to_json
  end
  let(:item) do
    k = key_data
    Class.new(Sequel::Model(:items)) do
      include AttrVault
      vault_keyring k
      vault_attr :secret
    end
  end

  it "works" do
    3.times.map do
      Thread.new do
        s = item.create(secret: 'that Commander Keen level in DOOM II')
        1_000.times do
          new_secret = [ nil, '', 36.times.map { (0..255).to_a.sample.chr }.join('') ].sample
          s.update(secret: new_secret)
          s.reload
          expect(s.secret).to eq new_secret
        end
      end
    end.map(&:join)
  end
end
