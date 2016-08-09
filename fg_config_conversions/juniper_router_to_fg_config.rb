require juniper_hash.rb
hash_config = Hash.new
hash_config = JuniperHash.get_hash(File.open('juniper_objects.conf').read)
p hash_config