require 'trollop' ## must install gem
require 'ipaddress' ## must install gem
require 'pp'   #included in ruby standard
require 'json' #included in ruby standard
require 'set'  #included in ruby standard

# Trollop: Handle Input Options and defaults
opts = Trollop::options {
  version 'junos2fg.rb v0.2'
  banner <<-EOS
Usage:
    junos2fg [options] <filenames>+
where [options] are:
  EOS

  opt :filein, 'Configuration File', :type => :string, :default => 'config.conf', :short => '-i'
  opt :fileout, 'Configuration File', :type => :string, :default => 'fg.out', :short => '-o'
  opt :debug, 'Turn on detailed messaging', :short => '-d'
  opt :dscpmapfile, 'File for mapping dscp class to bin', :default => 'ref/dscp_map.txt'
}
# Argument Checks
Trollop::die :filein, ",#{Dir.pwd}/#{opts[:filein]} does not exist" unless File.exist?(opts[:filein])


#########################
### Methods #############
#########################

def process_acls_extended(conffile)
  h = Hash.new
  file = File.readlines(conffile)
  linecount = 0

  file.each_with_index do |line, index|
    linecount += 1
    line = line.split

    # Find lines defining a class-map (only supporting type match-any)
    if line.at(0) == 'ip' && line.at(1) == 'access-list' && line.at(2) == 'extended'
      aclname = line.at(3)
      h[aclname] = Hash.new

      continue = true
      i = 0

      # Find match directives for the above class-map
      while continue
        i += 1

        #Have to look forward to the next lines to find the related config data (filter info)
        nextline = file[index+i]
        nextline = nextline.split

        # Ensure subsequent lines are permit or deny, if so, process them for this aclname
        if nextline.at(0) == 'permit' || nextline.at(0) == 'deny'
          h[aclname][i] = {:protocol => nil, :srcaddr => nil, :srcmask => nil, :srcport => nil,
                                     :dstaddr => nil, :dstmask => nil, :dstport => nil}

          # Check/set protoccol
          if %w[ip tcp udp icmp gre].include?(nextline.at(1))
            protocol = nextline.at(1)
            h[aclname][i][:protocol] = protocol
          else
            p "process_acls_extended: didn't match a protocol #{nextline.at(1)}, config line: #{linecount + i}"
            next
          end

          # Initialize Tracking Vars
          dstoffset = 4
          srcaddr = nil
          srcmask = nil
          srcport = nil
          dstaddr = nil
          dstmask = nil
          dstport = nil

          # Check/set SOURCE detail
          if IPAddress.valid?(nextline.at(2))
            srcaddr = nextline.at(2)
            srcmask = nextline.at(3)

            # Have to invert cisco's mask !!dumb
            oct1, oct2, oct3, oct4 = srcmask.split('.')
            oct1 = 255 - oct1.to_i
            oct2 = 255 - oct2.to_i
            oct3 = 255 - oct3.to_i
            oct4 = 255 - oct4.to_i
            srcmask = oct1.to_s + '.' + oct2.to_s + '.' + oct3.to_s + '.' + oct4.to_s

            # Check for source port specification
            if nextline.at(4) == 'eq'
               srcport= nextline.at(5)
              dstoffset += 2
            end

          elsif nextline.at(2) == 'any'
            srcaddr = 'all'
            srcmask = '0.0.0.0'
            dstoffset -= 1

            if nextline.at(3) == 'eq'
              srcport = nextline.at(4)
              dstoffset += 2
            end

          elsif nextline.at(2) == 'host'
            srcaddr = nextline.at(3)
            srcmask = '255.255.255.255'

            if nextline.at(4) == 'eq'
              srcport = nextline.at(5)
              dstoffset += 2
            end

          else
            p "process_acls_extended: src field is not valid ip, any, or host: #{nextline.at(2)}"
            h[aclname].delete(i)
            next
          end

          h[aclname][i][:srcaddr] = srcaddr
          h[aclname][i][:srcmask] = srcmask
          h[aclname][i][:srcport] = srcport

          # Process DESTINATION details
          if IPAddress.valid?(nextline.at(dstoffset))
            dstaddr = nextline.at(dstoffset)
            dstmask = nextline.at(dstoffset + 1)

            # Have to invert cisco's mask !dumb!
            oct1, oct2, oct3, oct4 = dstmask.split('.')
            oct1 = 255 - oct1.to_i
            oct2 = 255 - oct2.to_i
            oct3 = 255 - oct3.to_i
            oct4 = 255 - oct4.to_i
            dstmask = oct1.to_s + '.' + oct2.to_s + '.' + oct3.to_s + '.' + oct4.to_s

            if nextline.at(dstoffset + 2) == 'eq'
              dstport = nextline.at(dstoffset + 2)
            end

          elsif nextline.at(dstoffset) == 'any'
            dstaddr = 'all'
            dstmask = '0.0.0.0'

            if nextline.at(dstoffset + 1) == 'eq'
              dstport = nextline.at(dstoffset + 2)
            end

          elsif nextline.at(dstoffset) == 'host'
            dstaddr = nextline.at(4)
            dstmask = '255.255.255.255'

            if nextline.at(dstoffset + 2) == 'eq'
              dstport = nextline.at(dstoffset + 2)
            end

          else
            p "process_acls_extended: dstip fields not ip, any, or host: #{nextline.at(2)}"
            h[aclname].delete(i)
            next
          end

          h[aclname][i][:dstaddr] = dstaddr
          h[aclname][i][:dstmask] = dstmask
          h[aclname][i][:dstport] = dstport

        else
          continue = false
        end
      end
    end
  end

  return h

end

def process_class_map(conffile)
  h = Hash.new
  file = File.readlines(conffile)
  linecount = 0
  file.each_with_index do |line, index|
    linecount += 1
    line = line.split

    # Find lines defining a class-map (only supporting type match-any)
    if line.at(0) == 'class-map' && line.at(1) == 'match-any'
      classmap = line.at(2)

      # Create the remaining hash structure for later use
      h[classmap] = {'access-group' => Set.new, 'dscp' => Set.new}

      continue = true
      i = 0

      # Find match directives for the above class-map
      while continue
        i += 1

        nextline = file[index+i]
        nextline = nextline.split

        if nextline.at(0) == 'match' && nextline.at(1) == 'access-group'
          h[classmap]['access-group'] << nextline.at(3)

        elsif nextline.at(0) == 'match' && nextline.at(1) == 'dscp'
          h[classmap]['dscp'] << nextline.at(2)

        elsif nextline.at(0) == 'match'
          p "process_class_map: class-map match type not supported @line #{linecount += i}"

        else
          continue = false
        end
      end
    end
  end

  return h
end

def process_policy_map(conffile)
  h = Hash.new
  file = File.readlines(conffile)
  linecount = 0

  file.each_with_index do |line, index|
    linecount += 1
    line = line.split

    # Find lines defining a class-map (only supporting type match-any)
    if line.at(0) == 'policy-map'
      policymap = line.at(1)
      h[policymap] = Hash.new

      continue = true
      classmap = String.new
      i = 0

      # Find match directives for the above class-map
      while continue
        i += 1

        # Need to look ahead to following lines for data related to this policy map
        nextline = file[index+i]
        nextline = nextline.split

        # If line defines class reference....
        if nextline.at(0) == 'class'
          classmap = nextline.at(1)
          h[policymap][classmap] = Hash.new

        # If line defines the dscp value to set...
        elsif nextline.at(0) == 'set' && nextline.at(1) == 'dscp'
          dscpval = nextline.at(2)
          h[policymap][classmap]['set-dscp'] = dscpval

        else
          continue = false
        end
      end
    end
  end

  return h
end

def dscp_file_map(mapfile)

  h = Hash.new
  file = File.open(mapfile, 'r')

  file.each_line do |x|
    key, val = x.split
    h[key] = val
  end

  file.close
  return h
end





##### Main #####
# declare vars
h_dscp_map = Hash.new
h_acls_extended = Hash.new
h_class_map = Hash.new
h_policy_map = Hash.new

# Get hashses config config objects and mappings
h_acls_extended = process_acls_extended(opts[:filein])
h_class_maps = process_class_map(opts[:filein])
h_policy_maps = process_policy_map(opts[:filein])
h_dscp_map = dscp_file_map(opts[:dscpmapfile])


### Quick stdout for objects
#pp h_dscp_map
#pp h_class_maps
#pp h_policy_maps
pp h_acls_extended