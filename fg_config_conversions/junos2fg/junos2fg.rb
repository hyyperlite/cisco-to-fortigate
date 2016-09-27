# Converts Junos Router filters/terms to FortiGate 5.4 address objects, service objects and policies
# Only tested with config file from Junos 11.4R7.5 but may work with others
# currently does not support converting the following:
#  * converting forwarding-classes
#  * no qos/class of service (aka fg traffic shaping translation)
#  * VPLS policies are currently ignored
#  * because converting from stateless to stateful device, tcp-established terms are ignored

require 'trollop' ## must install gem
require 'ipaddress' ## must install gem
require 'pp'   #included in ruby standard
require 'json' #included in ruby standard
require 'set'  #included in ruby standard

# Trollop: Handle Input Options and defaults
$opts = Trollop::options {
  version 'junos2fg.rb v0.2'
  banner <<-EOS
Usage:
    junos2fg [options] <filenames>+
where [options] are:
EOS

  opt :junosin, 'Configuration File', :type => :string, :default => 'junos.conf', :short => '-i'
  opt :fgout, 'Configuration File', :type => :string, :default => 'junos2fg.out', :short => '-o'
  opt :debug, 'Turn on detailed messaging', :short => '-d'
  opt :verbose, 'Enable process details', :short => '-v'
  opt :nostats, 'Disable statistical output', :short => '-n'
  opt :v4filterprint, 'Pretty Print the list of junos ipv4filters. Note: filters included affected by other options'
  opt :v6filterprint, 'Pretty Print the list of junos ipv6filters. Note: filters included affected by other options'
  opt :servicecategory, 'Category to assign service objects to', :type => :string, :default => 'converted'
  opt :v4inputfilters, 'Create FG configuration for v4 input filters'
  opt :v4outputfilters, 'Create FG configuration for v4 output filters'
  opt :v6inputfilters, 'Create FG configuration for v6 input filters'
  opt :v6outputfilters, 'Create FG configuration for v6 output filters'
  opt :skipaddresses, 'Do not create fg configuration for address objects'
  opt :skipservices, 'Do not create fg configuraton for service objects'
  opt :map2sub, 'Map policies with dstaddr \'any\', to subnet of egress intf'
  opt :interfacemapout, 'For outputfilteres map output juniper intf to fg interface or zone using supplied map file',\
        :type => :string
}
# Argument Checks
Trollop::die :junosin, ",#{Dir.pwd}/#{$opts[:junosin]} does not exist" unless File.exist?($opts[:junosin])

Trollop::die :interfacemapout, ", #{Dir.pwd}/#{$opts[:interfacemapout]} does not exist"\
              unless File.exist?($opts[:interfacemapout]) if $opts[:interfacemapout]

##################################################
### Methods
##################################################

# Extract junos acl detail and save to hash $h_filters (ipv4) or $h_filters6 (ipv6) for later use
def process_firewall(fw)

  # Make sure the record is of firewall sub-type family
  if fw.at(2) == :family
    # Make sure the record is and ipv4 firewall filter
    if fw.at(3) == :inet  && fw.at(4) == :filter
        # Ensure that a "term" has been specified then create the first key "filter"
        if fw.at(6) == :term
          $h_filters[fw.at(5)] = {} unless $h_filters.has_key?(fw.at(5))

          # Add the terms to the filter hashes and create the term hash structure
          unless $h_filters[fw.at(5)].has_key?(fw.at(7))
            $h_filters[fw.at(5)][fw.at(7)] = {\
            :source => Hash.new,\
            :action => nil,\
            :'forwarding-class' => nil,\
            :'loss-priority' => nil,\
            :policer => nil}

            # count the number of total terms processed
            $ipv4_term_count += 1
          end

          # Populate term details (sources (and source type), action, forwarding-classs, loss-priority)
          case fw.at(8)
            ### Fill in term sources (extracted from fw.at(9) when definition type is "from")
            when :from
              $h_filters[fw.at(5)][fw.at(7)][:source][fw.at(10)] = fw.at(9)
              $ipv4_term_source_address += 1 if fw.at(9) == :'source-address'
              $ipv4_term_source_port += 1 if fw.at(9) == :'source-port'
              $ipv4_term_destination_address += 1 if fw.at(9) == :'destination-address'
              $ipv4_term_destination_port += 1 if fw.at(9) == :'destination-port'
              $ipv4_term_dscp += 1 if fw.at(9) == :dscp
              $ipv4_term_forwarding_class +=1 if fw.at(9) == :'forwarding-class'

            # action/forwarding-class/loss-priority
            when :then
              case fw.at(9)
                when :accept
                  $h_filters[fw.at(5)][fw.at(7)][:action] = fw.at(9)
                when :discard
                  $h_filters[fw.at(5)][fw.at(7)][:action] = fw.at(9)
                when :reject
                  $h_filters[fw.at(5)][fw.at(7)][:action] = fw.at(9)
                when :'forwarding-class'
                  $h_filters[fw.at(5)][fw.at(7)][:'forwarding-class'] = fw.at(10)
                when :'loss-priority'
                  $h_filters[fw.at(5)][fw.at(7)][:'loss-priority'] = fw.at(10)
                when :'policer'
                  $h_filters[fw.at(5)][fw.at(7)][:policer] = fw.at(10)
                else
                  if $opts[:verbose]
                    p "ipv4 filter: action-type not supported, skipping: #{fw.at(9)} --> #{fw.at(10)}"\
                    unless fw.at(9) == :count
                  end
              end
            # other filter object reference
            when :filter
              $h_filters[fw.at(5)][fw.at(7)][:source][fw.at(9)] = :filter
          end
        end

    # IPv6 FW filter processing
    elsif fw.at(3) == :inet6 && fw.at(4) == :filter

      # Ensure that a "term" has been specified then create the first key "filter"
      if fw.at(6) == :term
        $h_filters6[fw.at(5)] = {} unless $h_filters6.has_key?(fw.at(5))

        # Add the terms to the filter hashes and create the term detail hash structure
        unless $h_filters6[fw.at(5)].has_key?(fw.at(7))
          $h_filters6[fw.at(5)][fw.at(7)] = {:source => Hash.new, :action => nil, :'forwarding-class' => nil,\
                                             :'loss-priority' => nil, :policer => nil}

          $ipv6_term_count += 1
        end

        # Populate term details, sources and source type as hash entries to $h_entries
        case fw.at(8)

          # source detail
          when :from
            $h_filters6[fw.at(5)][fw.at(7)][:source][fw.at(10)] = fw.at(9)
            $ipv6_term_source_address += 1 if fw.at(9) == :'source-address'
            $ipv6_term_source_port += 1 if fw.at(9) == :'source-port'
            $ipv6_term_destination_address += 1 if fw.at(9) == :'destination-address'
            $ipv6_term_destination_port += 1 if fw.at(9) == :'destination-port'
            $ipv6_term_dscp += 1 if fw.at(9) == :dscp
            $ipv6_term_forwarding_class += 1 if fw.at(9) == :'forwarding-class'

          # add action/forwarding-class/loss-priority/etc options to $h_filter entries if they exist
          when :then
            case fw.at(9)
              when :accept
                $h_filters6[fw.at(5)][fw.at(7)][:action] = fw.at(9)
              when :discard
                $h_filters6[fw.at(5)][fw.at(7)][:action] = fw.at(9)
              when :reject
                $h_filters6[fw.at(5)][fw.at(7)][:action] = fw.at(9)
              when :'forwarding-class'
                $h_filters6[fw.at(5)][fw.at(7)][:'forwarding-class'] = fw.at(10)
              when :'loss-priority'
                $h_filters6[fw.at(5)][fw.at(7)][:'loss-priority'] = fw.at(10)
              when :'policer'
                $h_filters6[fw.at(5)][fw.at(7)][:policer] = fw.at(10)
              else
                if $opts[:verbose]
                  p "ipv6 filter: action-type not supported, skipping: #{fw.at(9)} --> #{fw.at(10)}"\
                  unless fw.at(9) == :count
                end
            end
          # other filter object reference
          when :filter
            $h_filters6[fw.at(5)][fw.at(7)][:source][fw.at(9)] = :filter
        end
      end

    # If this is a VPLS firewall filter, for now we are noting it in output but taking no action
    # as vpls isn't easily translatable to FortiGate
    elsif fw.at(3) == :vpls && fw.at(4) == :filter
      p 'process_firewall: no action taken on vpls filters' if $opts[:verbose]
    else
      return
    end

  # If this is not a firewall filter and is instead a policer definition
  elsif fw.at(2) == "policer"
    p 'firewall: no action taken on policiers' if $opts[:debug]
  else
    p "firewall: unsupported firewall option, #{fw.at(2)}" if $opts[:verbose]
  end

end

# Extract junos policy-options detail and save to $h_policy_statements for later use
def process_policy_options(po)

  if po.at(2) == :'prefix-list'
    unless $h_prefix_lists.has_key?(po.at(3))
      $h_prefix_lists[po.at(3)] = Array.new
      $prefix_list_count += 1
    end

    $h_prefix_lists[po.at(3)] << po.at(4)
    $prefix_list_address_count += 1

  elsif po.at(2) == :'policy-statement'
    unless $h_policy_statements.has_key?(po.at(3))
      $h_policy_statements[po.at(3)] = Hash.new
      $policy_statement_count += 1
    end
    unless $h_policy_statements[po.at(3)].has_key?(po.at(5))
      $h_policy_statements[po.at(3)][po.at(5)] = {:source => Hash.new, :action => nil, :metric => nil, \
      :'next-hop' => nil, :tag => nil, :origin => nil, :pref => nil, :'local-pref' => nil, :next => nil, \
      :'lb-perpacket' => nil}

      $policy_statement_term_count += 1
    end

    # Populate policy-statement term details
    case po.at(6)
      # source detail
      when :from
        $h_policy_statements[po.at(3)][po.at(5)][:source][po.at(8)] = po.at(7)

      # actions
      when :then
        case po.at(7)
          when :accept
            $h_policy_statements[po.at(3)][po.at(5)][:action] = po.at(7)
          when :discard
            $h_policy_statements[po.at(3)][po.at(5)][:action] = po.at(7)
          when :reject
            $h_policy_statements[po.at(3)][po.at(5)][:action] = po.at(7)
          when :metric
            $h_policy_statements[po.at(3)][po.at(5)][:metric] = po.at(8)
          when :'next-hop'
            $h_policy_statements[po.at(3)][po.at(5)][:'next-hop'] = po.at(8)
          when :tag
            $h_policy_statements[po.at(3)][po.at(5)][:tag] = po.at(9)
          when :origin
            $h_policy_statements[po.at(3)][po.at(5)][:origin] = po.at(8)
          when :'local-preference'
            $h_policy_statements[po.at(3)][po.at(5)][:'local-pref'] = po.at(8)
          when :preference
            $h_policy_statements[po.at(3)][po.at(5)][:pref] = po.at(8)
          when :next
            $h_policy_statements[po.at(3)][po.at(5)][:next] = po.at(8)
          else
             p "policy-statement: action-type not supported, skipping: #{po.at(7)} --> #{po.at(8)}" if $opts[:verbose]
        end
    end

  else
    p "policy-option: type not supported, skipping: #{po.at(2)}" if $opts[:verbose]
  end
end

# This method parses the juniper configuration to identify all interfaces/units
# it then stores the detail of each unique interface/units (aka sub-interface) to a global
# array $h_interfaces.
def process_interfaces(int)

  # if unit is not the 4th field then this specified interface settings we don't care about
  # return to main to receive the next line or to move on to another method
  return if int.at(3) != :unit

  # if the primary interface (not unit) has not already been added as a key to the hash
  # go ahead and add it.  Otherwise continue to process unit values.
  unless $h_interfaces.has_key?(int.at(2))
    $h_interfaces[int.at(2)] = Hash.new
  end

  unless $h_interfaces[int.at(2)].has_key?(int.at(4))
    $h_interfaces[int.at(2)][int.at(4)] = {\
     :description => nil, \
     :'address_v4_primary' => nil,\
     :'ipv4_input_filter' => nil,\
     :'ipv4_output_filter' => nil,\
     :'address_v6_primary' => nil,\
     :'ipv6_input_filter' => nil,\
     :'ipv6_output_filter' => 'nil',\
     :vlan => nil,\
     :vrrp => Hash.new}

    $interface_count += 1
  end

  # IP address info
  if (int.at(6) == :inet && int.at(7) == :address) && (int.at(9) == :primary || int.at(9) == nil)
    $h_interfaces[int.at(2)][int.at(4)][:'address_v4_primary'] = int.at(8)
  end
  if (int.at(6) == :inet6 && int.at(7) == :address) && (int.at(9) == :primary || int.at(9) == nil)
    $h_interfaces[int.at(2)][int.at(4)][:'address_v6_primary'] = int.at(8)
  end

  # Set Interface Description
  $h_interfaces[int.at(2)][int.at(4)][:description] = int.at(6) if int.at(5) == :description

  # Set vlan-id
  $h_interfaces[int.at(2)][int.at(4)][:vlan] = int.at(6) if int.at(5) == :'vlan-id'

  # Set input/output filters
  if int.at(6) == :inet && int.at(7) == :filter && int.at(8) == :input
    $h_interfaces[int.at(2)][int.at(4)][:ipv4_input_filter] = int.at(9)
    $ipv4_uniq_inputfilter_count << int.at(9)
  end
  if int.at(6) == :inet && int.at(7) == :filter && int.at(8) == :output
    $h_interfaces[int.at(2)][int.at(4)][:ipv4_output_filter] = int.at(9)
    $ipv4_uniq_outputfilter_count << int.at(9)
  end
  if int.at(6) == :inet6 && int.at(7) == :filter && int.at(8) == :input
    $h_interfaces[int.at(2)][int.at(4)][:ipv6_input_filter] = int.at(9)
    $ipv6_uniq_inputfilter_count << int.at(9)
  end
  if int.at(6) == :inet6 && int.at(7) == :filter && int.at(8) == :output
    $h_interfaces[int.at(2)][int.at(4)][:ipv6_output_filter] = int.at(9)
    $ipv6_uniq_outputfilter_count << int.at(9)
  end

  # VRRP Detail
  if int.at(9) == :'vrrp-group'
    unless $h_interfaces[int.at(2)][int.at(4)][:vrrp].has_key?(int.at(10))
      $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)] = {\
      :'virtual-address' => nil,\
      :'intf-address' => nil,\
      :priority => nil,\
      :'advertise-interval' => nil,\
      :preempt => nil,\
      :'accept-data' => nil,\
      :'authentication-type' => nil,\
      :'authentication-key' => nil }

      $vrrp_group_count += 1
    end

    $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:'intf-address'] = int.at(8)

    # For other interface parameters, add a key for each under the interface/unit array
    case int.at(11)
      when :'virtual-address'
        $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:'virtual-address'] = int.at(12)
      when :priority
        $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:priority] = int.at(12)
      when :'advertise-interval'
        $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:'advertise-interval'] = int.at(12)
      when :preempt
        $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:preempt] = :true
      when :'accept-data'
        $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:'accept-data'] = :true
      when :'authentication-type'
        $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:'authentication-type'] = int.at(12)
      when :'authentication-key'
        $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)][:'authentication-key'] = int.at(12)
    end

  end

end

# if option :interfacemapout then build a hash of junos interfaces to fg interface/zone mappings
def process_map_interface

  # Initialize vars
  h_ints_map_out = Hash.new

  # open the file with list of interfaces to process, and zone to map each to
  intsfile = File.open($opts[:interfacemapout], 'r')

  intsfile.each_line do |x|
    key, val = x.split
    h_ints_map_out[key] = val
  end

  intsfile.close
  return h_ints_map_out
end

# From file: workingdir/reference/dscp_map.txt build a hash of dscp tags to dscp binary values
def process_map_dscp
  # Initialize vars
  h_dscp_map = Hash.new

  # open the file with list of interfaces to process, and zone to map each to
  dscpfile = File.open('reference/dscp_map.txt', 'r')

  dscpfile.each_line do |x|
    key, val = x.split
    h_dscp_map[key] = val
    #p "#{key}, #{val}"
  end

  dscpfile.close
  return h_dscp_map
end
# Method orchestrations the translation of juniper source-addres, destination-address, prefix,
# source-prefix and destination-prefix objects into FG address object configuration.
# Method first assesses whether a particular filter is used by an interface.  If not, the filter
# is skipped in order to avoid adding unused address objects to FG config
def create_address_objects

  # Initialize vars
  a_addresses = Array.new
  a_prefix_lists = Array.new
  config = String.new
  filterused = nil


  # Combining ipv4 and ipv6 filters to a single hash to process both simultaneously
  filters = $h_filters.merge($h_filters6)

  filters.each_key do |filtername|

    # check_if_filter_used returns 1 if this filter is used by an interface 0 if not
    filterused = check_if_filter_used(filtername)

    unless filterused
      p "create_fgpolicy_address_objects: filter is not used by an interface. skipping filtername: #{filtername}"\
        if $opts[:debug]
      next
    end

    filters[filtername].each_key do |termname|
      filters[filtername][termname][:source].each do |sourcename, sourcetype|
          if sourcetype == :'source-address' || sourcetype == :'destination-address'

            # Adding all to new hash in order to remove duplicates
            a_addresses << sourcename
          end

          if sourcetype == :'source-prefix-list' ||\
             sourcetype == :'destination-prefix-list' ||\
             sourcetype == :'prefix-list'
            a_prefix_lists << sourcename
            a_prefix_lists.uniq.each do |prefixlist|
              if $h_prefix_lists.has_key?(prefixlist)
                $h_prefix_lists[prefixlist].each do |prefixadds|
                  a_addresses << prefixadds
                end
              else
                p "create_address_objects: Referenced prefix #{sourcename} could not be found.\\
                  Filter: #{filtername}, term: #{termname}"
              end
            end
          end

      end
    end
  end

  # create a fg config entry for each uniq address identified
  config += "#### Address Objects ####\n"
  config += "config firewall address\n"
  a_addresses.uniq.each do |x|

    fgaddress = <<-EOS
  edit #{x}
    set type subnet
    set subnet #{x}
  next
  EOS

    # Add each output from Herdoc above to config var (will pass this back to main)
    config += fgaddress
  end

  config += "end\n"
  config += "#### Addresses Groups###\n"
  config += "config firewall addrgroup\n"

  $h_prefix_lists.each do |prefixlist, prefixadds|

    # Convert array to string usable in addrgroup config
    adds = String.new
    prefixadds.each {|x| adds += "#{x.to_s} "}

    fggroups = <<-EOS
  edit #{prefixlist}
    set member #{adds}
  next
    EOS

    config += fggroups
  end

  # Return this pieces of FG config to main for additional methods to add to it
  config += "end\n\n"

end

# give a filtername, check if the filter is used by any interfaces in the config
# if option interfacemap was provided, also check to see if supplied interfaces match
def check_if_filter_used(filtername)

  # define vars
  filterused = nil

  # Check to see if filter is used by an interface
  $h_interfaces.each_key do |int|
    $h_interfaces[int].each_key do |sub|
      if $h_interfaces[int][sub][:ipv4_input_filter] == filtername ||\
           $h_interfaces[int][sub][:ipv6_input_filter] == filtername ||\
           $h_interfaces[int][sub][:ipv4_output_filter] == filtername ||\
           $h_interfaces[int][sub][:ipv6_output_filter] == filtername
        filterused = true
      end

      # added in to support new request to process specific interfaces
      # for performance this check should occur before parsing all interfaces above
      # but for expediency it is here right now.  Will move later  *update*
      if $opts[:interfacemapout] && filterused
        $h_ints_map_out.each_key do |x|
          filterused = nil unless x == "#{int}-#{sub}"
          return filterused if filterused
        end
      end
      return filterused
    end
  end
end

# This method orchestrates the analysis of juniper protocol definitions
# and translates them to a config file of fortigate service objects
# By default, this method skips any objects that are in filters which
# are not used by an interface (aka orphaned)
# This method calls the config_fgservice method for creating the fg configuration for each object
def create_service_objects

  # initialize vars
  svcconfig = String.new
  svcconfig = "#### Service Objects ####\n"
  svcconfig += "config firewall service custom"
  service_tracker = Set.new   # create a set for tracking if service already has been created to avoid duplicates
  category = $opts[:servicecategory]
  filterused = nil

  # Open external files with data for mapping protocol port numbers
  ip = File.open 'reference/ip_protocol_nums.txt', 'r'
  tcpudp = File.open 'reference/tcp-udp_ports.txt', 'r'
  icmp = File.open 'reference/icmp_type_codes.txt', 'r'
  icmpmsg = File.open 'reference/icmp_msg_codes.txt', 'r'

  # Initialize hashes for stroing the protocol/port number information from files
  h_ip = Hash.new
  h_tcpudp = Hash.new
  h_icmp = Hash.new
  h_icmp_msg = Hash.new

  # import the ip protocol number info from file to h_ip hash
  ip.each_line do |x|
    num, name = x.split
    h_ip[num] = name
  end

  # reverse the keys and values
  h_ip = h_ip.invert

  # import the tcp/dump port number info from file to h_tcpudp hash
  tcpudp.each_line do |x|
    num, name = x.split
    h_tcpudp[num] = name
  end

  # reverse the keys and values
  h_tcpudp = h_tcpudp.invert

  # import the icmp type code detail from file to the h_icmp hash
  icmp.each_line do |x|
    num, name = x.split
    h_icmp[num] = name
  end

  # import the icmp msg code detail from file to the h_icmp_msg hash
  icmpmsg.each_line do |x|
    num, name = x.split
    h_icmp_msg[num] = name
  end

  # close the protocol info files
  ip.close
  tcpudp.close
  icmp.close
  icmpmsg.close

  # Create a new service category in the local fg config file to assign all created services to
  svcconfig = <<-EOS
config firewall service category
  edit #{category}
end

EOS

  # Merge ipv4 and ipv6 filters to hash "filters" to process both ipv4 and ipv6 in this request
  filters = $h_filters.merge($h_filters6)

  # Process service objects for all ipv4 filters first
  filters.each_key do |filtername|
    filterused = check_if_filter_used(filtername)

    unless filterused
      p "policy_service_objects: filter not used by an interface, skipping: #{filtername}" if $opts[:verbose]
      next
    end


    filters[filtername].each_key do |termname|
       filters[filtername][termname][:source].each do |sourcename, sourcetype|

        # Use sourcetype to identify service definitions then modify those as needed to
        # convert for use in FG config
        case sourcetype.to_s   # we will be matching against strings and output to string so need to chg from symbol
          when *%w[destination-port source-port port]

            # Matching anything that is all digits or digits with a single dash
            # the just digits indicates a single port number while with a dash is a range.
            # anything that does not match these will be processed in subsequent case
            # as we'll need to map those from words "http, ftp, etc" to port numbers
            if /^(\d+)$/ =~ sourcename || /^(\d+[-]\d+)$/ =~ sourcename

              ### Some entries contain a range of ports.  In these cases
              ### we need to split the low and high ports for assignment
              lowport, highport = ''
              lowport, highport = sourcename.to_s.split('-')

              highport = lowport unless highport

              ### Check to see if the associated term defines tcp, udp or icmp
              ### if it defines none of these then we will create objects for
              ### both tcp and udp.  It defines just icmp, we won't worry about the
              ### tcp/udp objects and will process icmp under a different case
              tcp, udp, icmp = nil
              if filters[filtername][termname][:source].has_key?(:tcp)
                tcp = 1
              end

              if filters[filtername][termname][:source].has_key?(:udp)
                udp = 1
              end

              if filters[filtername][termname][:source].has_key?(:icmp)
                icmp = 1
              end
             unless tcp && udp && icmp
               tcp = 1
               udp = 1
             end

              # create a tcp destination object if term contains protocol tcp and if
              # it's not type source-port and if we haven't already created this object
              if (tcp == 1 && !service_tracker.include?("#{sourcename}-tcp") && sourcetype != :'source-port')
                svcconfig += config_fgservice("#{sourcename}-tcp", lowport, highport, "from term: #{termname}",\
                                              category, :dst, :tcp)
                service_tracker.add("#{sourcename}-tcp")
              end

              if (udp == 1 && !service_tracker.include?("#{sourcename}-udp") && sourcetype != :'source-port')
                svcconfig += config_fgservice("#{sourcename}-udp", lowport, highport, "from term: #{termname}",\
                                              category, :dst, :udp)
                service_tracker.add("#{sourcename}-udp")
              end

              if (tcp == 1 && !service_tracker.include?("#{sourcename}-tcp") && sourcetype == :'source-port')
                svcconfig += config_fgservice("#{sourcename}-tcp_source", lowport, highport, "from term: #{termname}",\
                                              category, :src, :tcp)
                service_tracker.add("#{sourcename}-tcp_source")
              end

              if (udp == 1 && !service_tracker.include?("#{sourcename}-udp") && sourcetype == :'source-port')
                svcconfig += config_fgservice("#{sourcename}-udp_source", lowport, highport, "from term: #{termname}",\
                                              category, :src, :udp)
                service_tracker.add("#{sourcename}-udp_source")
              end

            #  Map named protocol term definitions to ports  (aka http, ftp, snmp)
            else
              # Get port matching sourcename from h_tcpudp service/port mapping array
              port, lowport, highport = nil

              port = h_tcpudp[sourcename.to_s]
              # if port is nil then no match was found, print out some info and move to next record
              if port == nil
                p "Couldn't find a protocol match in file: Sourcename: #{sourcename} --> Port: #{port}"\
                  if $opts[:verbose]

                next
              end

              lowport, highport = port.split('-')
              highport = lowport unless highport

              # Check to see if the associated term defines tcp, udp or icmp
              # if it defines none of these then we will create objects for
              # both tcp and udp.  It defines just icmp, we won't worry about the
              # tcp/udp objects and will process icmp under a different case
              tcp, udp, icmp = nil
              if filters[filtername][termname][:source].has_key?(:tcp)
                tcp = 1
              end

              if filters[filtername][termname][:source].has_key?(:udp)
                udp = 1
              end

              if filters[filtername][termname][:source].has_key?(:icmp)
                icmp = 1
              end
              unless tcp && udp && icmp
                tcp = 1
                udp = 1
              end

              if (tcp == 1 && !service_tracker.include?("#{sourcename}-tcp") && sourcetype != :'source-port')
                svcconfig += config_fgservice("#{sourcename}-tcp", lowport, highport, "from term: #{termname}",\
                                              category, :dst, :tcp)

                service_tracker.add("#{sourcename}-tcp")
              end

              if (udp == 1 && !service_tracker.include?("#{sourcename}-udp") && sourcetype != :'source-port')
                svcconfig += config_fgservice("#{sourcename}-udp", lowport, highport, "from term: #{termname}",\
                                              category, :dst, :udp)

                service_tracker.add("#{sourcename}-udp")
              end

              if (tcp == 1 && !service_tracker.include?("#{sourcename}-tcp") && sourcetype == :'source-port')
                svcconfig += config_fgservice("#{sourcename}-tcp_source", lowport, highport, "from term: #{termname}",\
                                              category, :src, :tcp)
                service_tracker.add("#{sourcename}-tcp_source")
              end

              if (udp == 1 && !service_tracker.include?("#{sourcename}-udp") && sourcetype == :'source-port')
                svcconfig += config_fgservice("#{sourcename}-udp_source", lowport, highport, "from term: #{termname}",\
                                              category, :src, :udp)
                service_tracker.add("#{sourcename}-udp_source")
              end
            end


### Process ICMP protocol types

          when *%w[icmp-type icmp-type-except]
            port = String.new

            if /^(\d+)$/ =~ sourcename
              port = sourcename
            else
              port = h_icmp[sourcename.to_s]
            end

            if port and !service_tracker.include?(port)
              svcconfig += config_fgservice("ICMP-#{sourcename}", port, port, "from term: #{termname}",\
                                            category, :icmp, :icmp)

              service_tracker.add("ICMP-#{sourcename}")

            elsif !port
              p "create_fgpolicy_service_objects: service icmp-type not found port = #{port} sourcename = #{sourcename}"\
                if $opts[:verbose] || $opts[:debug]
              next
            end
        end
      end
    end
  end
  if $opts[:debug]
    p "service tracker"
    service_tracker.each do |x|
      p x
    end
  end

  # Return the resulting config to main execution
  svcconfig += "end\n\n"
end

# Method creates and returns configuration of a single FG service object
def config_fgservice(servicename, lowport, highport, comment, category, type, proto)

  config = String.new

#####################################
# TCP and Destination Entry
####################################
  if type == :dst && proto == :tcp

    fgservice = <<-EOS
  edit #{servicename}
    set tcp-portgrange #{lowport} #{highport}
    set category #{category}
    set comment "#{comment}"
  next
    EOS

    config += fgservice
  end

####################################
# UDP and Destination Entry
####################################
  if type == :dst && proto == :udp

    fgservice = <<-EOS
  edit #{servicename}
    set udp-portgrange #{lowport} #{highport}
    set category #{category}
    set comment "#{comment}"
  next
    EOS

    config += fgservice
  end

###################################
# TCP and Source Entry
####################################
  if type == :src && proto == :tcp

    fgservice = <<-EOS
  edit #{servicename}
    set tcp-portgrange 1 65535 #{lowport} #{highport}
    set category #{category}
    set comment "#{comment}"
  next
    EOS

    config += fgservice
  end

###################################
# UDP and Source Entry
####################################
  if type == :src && proto == :udp

    fgservice = <<-EOS
  edit #{servicename}
    set udp-portgrange 1 65535 #{lowport} #{highport}
    set category #{category}
    set comment "#{comment}"
  next
    EOS

    config += fgservice
  end

###################################
# ICMP Service Entry
####################################
  if type == :icmp && proto == :icmp

    fgservice = <<-EOS
  edit #{servicename}
    set protocol ICMP
    set  icmptype #{lowport}
    set category #{category}
    set comment "#{comment}"
  next
    EOS

    config += fgservice
  end

  return config
end

# Method orchestrates the creation of FG policy configuration by iterating through
# all filters and terms stored to the $h_filters and $h_filters6 arrays.
# This method calls get_rule_detail to retreive src,dst,srcport,dport,protocol,action from each filter/term
# This method calls config_fwrules to translate the output from get_rule_detail to FG object config
# This method returns policy configuration for the specified filter type, ipv4/ipv6 input/output
# Filtertype == one of :ipv4_input_filter, :ipv4_outputfilter, :ipv6_input_filter or :ipv6_output_filter
def create_policy(filtertype)

  # Initialize vars, sets, string, hashes, etc
  filter = String.new
  fwconfig = String.new
  result = String.new
  service_negate = String.new
  newaddresses = Set.new

  case filtertype
    when :ipv4_input_filter
      fwconfig += "#### Firewall Interface Policy ####\n"
      fwconfig += "config firewall interface-policy\n"
      h_filters = $h_filters
    when :ipv6_input_filter
      fwconfig += "#### Firewall IPv6 Interface Policy ####\n"
      fwconfig += "config firewall interface-policy6\n"
      h_filters = $h_filters6
    when :ipv4_output_filter
      fwconfig += "#### Firewall Policy ####\n"
      fwconfig += "config firewall policy\n"
      h_filters = $h_filters
    when :ipv6_output_filter
      fwconfig += "#### Firewall IPv6 Policy ####\n"
      fwconfig += "config firewall policy6\n"
      h_filters = $h_filters6
    else
      p "create_fg_intf_policy_rules:  filtertype not supported - #{filtertype}" if $opts[:verbose]
      return
  end

  # For each interface/sub-interface, process each unique filter matching the passed filtertype option
  # We are iterating through each used filter and checking the terms for compatibility.  If compatible
  # then we will go ahead and process/convert to FG config.
  $h_interfaces.each_key do |int|
    $h_interfaces[int].each_key do |sub|
      if ($opts[:interfacemapout] && $h_ints_map_out.has_key?("#{int}-#{sub}")) || !$opts[:interfacemapout]
        filter = $h_interfaces[int][sub][filtertype]

        ruletype = ''    # for supportability checks
        filterref = ''   # for referenced filters (aka linked filters)

        ### if interfacemapout option specified then we will change the dst interace to zone name supplied by file
        if $opts[:interfacemapout]
          interface = $h_ints_map_out["#{int}-#{sub}"]
        else
          interface = "#{int}-#{sub}"
        end

        unless filter == 'nil' || filter == nil
          if h_filters.has_key?(filter)
            h_filters[filter].each_key do |term|

              # check to see if this policy is derived from dscp, forwarding-class, etc. if so, we will skip
              ruletype, filterref = check_rule_support_type(filter, term, h_filters)

              # Call action_rule_support_type which will call the right methods to build the fg config
              # based on the juniper filter/term detail, including handling nested filters/terms
              # will return the completed FG config for that filter/term.  Also, if int2sub option is enabled
              # may return a list of subnets that need to be additionally created as address objects.
              newconfig, newaddobj = action_rule_support_type(ruletype,\
                                                   filterref,\
                                                   h_filters,\
                                                   filtertype,\
                                                   filter,\
                                                   term,\
                                                   interface,\
                                                   int,\
                                                   sub)

              fwconfig += newconfig

              # Add any new address objects that need to be configured to a set
              newaddresses << newaddobj if newaddobj
            end

          else
            p "create_fg_policy_rules: filter \"#{filter} referenced by interface does not exist for #{int}-#{sub}"\
              if $opts[:debug] || $opts[:verbose]
          end

        end
      else
        p "Skipping interface #{int}-#{sub} due to, is not included in --interfacemapout file"\
          if $opts[:debug] || $opts[:verbose]
      end
    end
  end
  fwconfig += "end \n"

  # If new address objects need to be created due that here, and insert them in the config ahead of creating
  # rules that will need to use these objects.
  if newaddresses.count > 0
    newconfig = "### Additional FW Addresses from derived subnets ###"
    newconfig += "config firewall address\n"

    newaddresses.each do |x|
      p "there are new addresses"
      newconfig += <<-EOS
  edit #{x}
    set type subnet
    set subnet #{x}
    set comment "Derived subnet from interface IP due to rule with dst of any"
  next
    EOS
    end

    newconfig += "end\n"

    fwconfig = newconfig + fwconfig
  end

  return fwconfig
 end

# Broke out of create_fg_policy_rules in order to support nested rules
# checks details of specified rule and returns info about the rule for
# further decision making about how to process the rule
def check_rule_support_type(filter, term, h_filters)

  # Initialize vars
  ruletype = :normal
  filterref = ''

  h_filters[filter][term][:source].each do |object, objtype|
    if objtype == :'forwarding-class' || objtype == :'tcp-established' || objtype == :filter
      ruletype = objtype
    end

    # If the type is :filter, this is a link to another entire filter (aka nested filter), we must pass back the name
    # of the referenced/nested filter and recurse that filter to get the details for this rule.
    filterref = object if objtype == :filter

    return ruletype, filterref unless ruletype == 'normal'
  end

  return ruletype, filterref
end

# Based on rule type and other data take specific actions to generate the rule,
# skip, or take some other action
def action_rule_support_type(ruletype, filterref, h_filters, filtertype, filter, term, interface, int, sub)

  fwconfig = String.new

  if ruletype == :normal

    # Call get_rule_detail to provide most relevant config detail related to this filter/term
    # The following are returned as sets from the get_rule_detail method
    srcaddr, dstaddr, sport, dport, protocol, service_negate, result, dscp = get_rule_detail(filtertype, filter, term)

    action = h_filters[filter][term][:action]  # *update* this 'action' set should be moved to get_rule_detail method

    # Using provided rule detail config_fwrules method will return the FG configuration for "normal" rules
    # this includes determining interfaces vs policy based rules
    newconfig, newaddobj = config_fwrules(filtertype,\
                               srcaddr,\
                               dstaddr,\
                               sport,\
                               dport,\
                               protocol,\
                               action,\
                               service_negate,\
                               interface,\
                               int,\
                               sub,\
                               filter,\
                               term,
                               dscp)

    fwconfig += newconfig

#     if newaddobj
#
#       fwconfig = <<-EOS
# config firewall address
#   edit #{newaddobj}
#     set type subnet
#     set subnet #{newaddobj}
#     set comment "derived from dst interface IP due to dst any in filter-term: #{filter}-#{term}"
# end
#   #{fwconfig}
#     EOS
#
#       p "new address object"
#     end

  ### If the ruletype is a filter, this is referencing a nested filter so we will supply this filter back up to
  ### check_rule_support_type method which will in turn call this method if it contains supported filters/rules
  elsif ruletype == :filter

    # Check to make sure that the nested filter referenced does in fact exist
    if h_filters.has_key?(filterref)
      h_filters[filterref].each_key do |termref|

        # Call check_rule_support_type method to determine the rule type and therefore parameters for actions to be
        # taken next.  returns the rule type, and... if it is a nested rule, returns the reference to the nested
        # filter name so that that filter can be processed in place of the rule currently being processed.
        refruletype, reffilterref = check_rule_support_type(filterref, termref, h_filters)

        # Now that we know the rule type. Call action_rule_support_type method passing the ruletype information
        # and the appropriate actions will be taken to configure this rule type. by finally calling config_fwrules
          newconfig, newaddobj = action_rule_support_type(refruletype,\
                                             reffilterref,\
                                             h_filters,\
                                             filtertype,\
                                             filter,\
                                             term,\
                                             interface,\
                                             int,\
                                             sub)

        fwconfig += newconfig
      end


    # If the nested filter referenced does not exist then output error to stdout and return empty config
    else
      p "action_rule_support_type: nested filter reference #{filterref} does not exist, referenced by filter:\\
        #{filter}, term: #{term} "

      fwconfig += ''
    end

  # If not ruletype or :normal or :filter then we do not currently support it.  Will print error and return
  # empty fg configuration
  else
    p "action_rule_support_type: unsupported source type: #{continue}, skipping: filter: #{filter}, term: #{term}"\
      if $opts[:verbose] || $opts[:debug]

    fwconfig += ''
  end

  return fwconfig += '', newaddobj
end

# Returns list of source addresses, destination addressess, source ports
# destination ports and protocols for a requested filter:term.  Requires
# options filtertype = :ipv4_input_filter, :ipv4_output_filter, ipv6_input_filter
# ipv6_output_filter.  filter = name of filter (should be type sym),
# term = name of filter (should be a symbol)
def get_rule_detail(filtertype, filter, term)

  # Check filtertype and assign correct global hash ($h_filters or $h_filters6) to filters
  case filtertype
    when :ipv4_input_filter
      filters = $h_filters
    when :ipv4_output_filter
      filters = $h_filters
    when :ipv6_input_filter
      filters = $h_filters6
    when :ipv6_output_filter
      filters = $h_filters6
    else
        p "get_rule_detail: filtertype not supported - #{filtertype}" if $opts[:debug]
  end

  # Initialize vars, sets, etc
  result = ''   ### To pass status back to calling method
  srcaddr = Set.new
  dstaddr = Set.new
  sport = Set.new
  dport = Set.new
  protocol = Set.new
  dscp = Set.new
  svcnegate = 'false'  ### if type icmp-except need to negate the rule

  # Update corresponding hash based on object type from term's sources hash branch
  filters[filter][term][:source].each do |object, objtype|

    case objtype
      when :'source-address'
        srcaddr.add(object)

      when :'destination-address'
        dstaddr.add(object)

      when :address
        srcaddr.add(object)
        dstaddr.add(object)

      when :'source-port'
        sport.add(object)

      when :'destination-port'
        dport.add(object)

      when :port
        dport.add(object)

      when :'source-prefix-list'
        srcaddr.add(object)

        # The following code snipet is no longer used, but can be activated to add each address in the prefix list
        # to the dstaddr set.  Instead, we are using the name to reference an address group that should
        # have been created for each prefix list
        # $h_prefix_lists[object].each do |addr|
        #   srcaddr.add(addr)
        # end

      when :'destination-prefix-list'
        dstaddr.add(object)

        # The following code snipet is no longer used, but can be activated to add each address in the prefix list
        # to the dstaddr set.  Instead, we are using the name to reference an address group that should
        # have been created for each prefix list
        # $h_prefix_lists[object].each do |addr|
        #  dstaddr.add(addr)
        # end

      when :'prefix-list'
        srcaddr.add(object)
        dstaddr.add(object)

      when :protocol
        protocol.add(object)

      when :'next-header'
        protocol.add(object)

      when :'icmp-type'
        protocol.add(:icmp)
        dport.add(object)

      when :'icmp-type-except'
        protocol.add(:icmp)
        dport.add(object)
        svcnegate = 'true'

      when :dscp
        dscp.add(object)

      else
        result += "get_rule_detail: object type: #{objtype}, not supported for filter: #{filter}, term: #{term}"
        p "get_rule_detail: object type: #{objtype}, not supported for filter: #{filter}, term: #{term}"\
          if $opts[:verbose] || $opts[:debug]
    end
  end

  return srcaddr, dstaddr, sport, dport, protocol, svcnegate, result, dscp
end

# This method translates juniper rule detail passed in (such as srcaddr, dstaddr, dport, action)
# into FG policy. This method returns the FG firewall policy associated to 1 single filter term
def config_fwrules(filtertype,\
                   srcaddr,\
                   dstaddr,\
                   sport,\
                   dport,\
                   protocol,\
                   action,\
                   svc_negate,\
                   interface,\
                   int,\
                   sub,\
                   filter,\
                   term,\
                   dscp)

  # Initialize
  newaddobj = false

  # Currently an "input filter" (v4 or v6) is being translated to a FG interface policy
  # interface policies can only specifically allow traffic (aka no action can be specified)
  if filtertype == :ipv4_input_filter || filtertype == :ipv6_input_filter
    unless action == :accept
      p "config_fwrules: action type must be accept for interface policy" if $opts[:verbose]
      return ''
    end
  end

  # if action not specified then assume it is accept.   *update* This should be verified.
  action = :accept if action == ''

  if filtertype == :ipv4_output_filter || filtertype == :ipv6_output_filter
    unless action == :accept || action == :discard
      p "config_fwrules: action type must be accept or discard, was #{action} for outbound policy filter: #{filter},\\
         term: #{term}" if $opts[:verbose]

      return ''
    end
  end

  # Initialize local vars, strings, hashes, sets, arrays
  fwconfig = String.new
 # fwconfig += "### From Filter: #{filter}, Term: #{term}\n"
  fwconfig += "  edit 0\n"
  fwconfig += "    set comment \"From Filter: #{filter}, Term: #{term}\" \n"
  srcaddr_out = String.new
  dstaddr_out = String.new
  service_out = String.new
  dscp_out = String.new

  # Put the srcaddr and dstaddrs in a string format acceptable for applying
  # to a FG firewall policy as srcaddr or dstaddr setting. (aka no punctuation, spaces only)
  if srcaddr.count > 0
    srcaddr.each do |x|
      srcaddr_out  += x.to_s + ' '
    end
  else
    srcaddr_out = 'all'
  end

  if dstaddr.count > 0
    dstaddr.each do |x|
      dstaddr_out += x.to_s + ' '
    end
  else
    if $opts[:map2sub]
      ### When map2sub enabled, any rules with dstaddr any will be changed from any to the subnet
      ### that the associated interfaces IP is in
      case filtertype
        when :ipv4_output_filter
          if $h_interfaces[int.to_sym][sub.to_sym][:'address_v4_primary'] == nil
            $h_interfaces[int.to_sym][sub.to_sym][:vrrp].each_key do |x|
              unless $h_interfaces[int.to_sym][sub.to_sym][:vrrp][x][:'intf-address'] == nil
                intip = IPAddress $h_interfaces[int.to_sym][sub.to_sym][:vrrp][x][:'intf-address'].to_s
                dstaddr_out = intip.network.to_s + '/' + intip.prefix.to_s
                newaddobj = true
              end
            end
          else
            intip = IPAddress $h_interfaces[int.to_sym][sub.to_sym][:address_v4_primary].to_s
            dstaddr_out = intip.network.to_s + '/' + intip.prefix.to_s
            newaddobj = true
          end
        when :ipv6_output_filter
          if $h_interfaces[int.to_sym][sub.to_sym][:'address_v6_primary'] == nil
            $h_interfaces[int.to_sym][sub.to_sym][:vrrp].each_key do |x|
              unless $h_interfaces[int.to_sym][sub.to_sym][:vrrp][x][:'intf-address'] == nil
                intip = IPAddress $h_interfaces[int.to_sym][sub.to_sym][:vrrp][x][:'intf-address'].to_s
                dstaddr_out = intip.network.to_s + '/' + intip.prefix.to_s
                newaddobj = true
              end
            end
          else
            intip = IPAddress $h_interfaces[int.to_sym][sub.to_sym][:address_v6_primary].to_s
            dstaddr_out = intip.network.to_s + '/' + intip.prefix.to_s
            newaddobj = true
          end
        else
          dstaddr_out = 'all'
      end
    else
      dstaddr_out = 'all'
    end
  end

  # For input filters we are creating an inbound interface policy
  if filtertype == :ipv4_input_filter || filtertype == :ipv6_input_filter
    fwconfig += "    set interface #{interface}\n"
    fwconfig += "    set srcaddr #{srcaddr_out}\n"
    fwconfig += "    set dstaddr #{dstaddr_out}\n"
  elsif filtertype == :ipv4_output_filter || filtertype == :ipv6_output_filter
    fwconfig += "    set srcintf any\n"
    fwconfig += "    set dstintf #{interface}\n"
    fwconfig += "    set srcaddr #{srcaddr_out}\n"
    fwconfig += "    set dstaddr #{dstaddr_out}\n"
    fwconfig += "    set action  #{action}\n"
    fwconfig += "    set schedule always\n"
  else
    p "config_fwrules: filtertype not supported, skipping #{filtertype}"
  end

  ## Create the source and/or destination services fg config
  if protocol.include?(:tcp)
    dport.each do |x|
      service_out += "#{x}-tcp "
    end
    sport.each do |x|
      service_out += "#{x}-tcp_source "
    end
  end
  if protocol.include?(:udp)
    dport.each do |x|
      service_out += "#{x}-udp "
    end
    sport.each do |x|
      service_out += "#{x}-udp_source "
    end
  end

  # If no protocol is specified in the term, then we will add tcp and udp.
  if !(protocol.include?(:tcp) || protocol.include?(:udp)  || protocol.include?(:icmp))
    dport.each do |x|
      service_out += "#{x}-tcp "
    end
    sport.each do |x|
      service_out += "#{x}-tcp_source "
    end
    dport.each do |x|
      service_out += "#{x}-udp "
    end
    sport.each do |x|
      service_out += "#{x}-udp_source "
    end
    elsif (protocol.include?(:tcp) || protocol.include?(:udp) || protocol.include?(:icmp)) &&\
           (dport.count == 0 && sport.count == 0)
    protocol.each do |x|
     service_out += "#{x.to_s.upcase} "
    end
    elsif protocol.include?(:icmp) && !(protocol.include?(:tcp) || protocol.include?(:udp))
      dport.each do |x|
        service_out += "ICMP-#{x} "
      end
  end

  service_out = 'ALL' if service_out == ''
  fwconfig += "    set service #{service_out} \n"

  if svc_negate == 'true'
    fwconfig += "    set service-negate enable \n"
  end

  # if dscp acls in configured create the dscp fg value
  if dscp.count > 0
    dscp.each do |x|

      if $h_dscp_map[x.to_s]
        dscpval = $h_dscp_map[x.to_s]
        dscp_out += dscpval + ' '
      else
        p "config_fw_fules: No DSCP mapping found for dscp: #{x.to_s}"
        next
      end

    fwconfig += "    set dscp-match enable \n"
    fwconfig += "    set dscp-value #{dscp_out} \n"
    fwconfig += "    set diffserv-forward enable \n"
    fwconfig += "    set diffserv-reverse enable \n"
    end
  end

  fwconfig += "  next\n"

  return fwconfig, dstaddr_out if newaddobj == true
  return fwconfig, nil
end

#########################################
### Main
#########################################
### open config file for reading
filein = File.open $opts[:junosin], 'r'

# Create global primary data hashes
$h_interfaces = Hash.new
$h_filters = Hash.new
$h_filters6 = Hash.new
$h_prefix_lists = Hash.new
$h_policy_statements = Hash.new
$h_ints_map_out = process_map_interface if $opts[:interfacemapout]
$h_dscp_map = process_map_dscp

# Create counters
linecount = 0
$ipv4_term_count = 0
$ipv4_term_accept = 0
$ipv4_term_reject = 0
$ipv4_term_discard = 0
$ipv4_term_policer = 0
$ipv4_term_source_address = 0
$ipv4_term_destination_address = 0
$ipv4_term_source_filter = 0
$ipv4_term_protocol = 0
$ipv4_term_source_port = 0
$ipv4_term_destination_port = 0
$ipv4_term_dscp = 0
$ipv4_term_forwarding_class = 0
$ipv4_uniq_inputfilter_count = Array.new
$ipv4_uniq_outputfilter_count = Array.new
$ipv6_term_count = 0
$ipv6_term_accept = 0
$ipv6_term_reject = 0
$ipv6_term_discard = 0
$ipv6_term_policer = 0
$ipv6_term_source_address = 0
$ipv6_term_destination_address = 0
$ipv6_term_source_filter = 0
$ipv6_term_protocol = 0
$ipv6_term_source_port = 0
$ipv6_term_destination_port = 0
$ipv6_term_dscp = 0
$ipv6_term_forwarding_class = 0
$ipv6_uniq_inputfilter_count = Array.new
$ipv6_uniq_outputfilter_count = Array.new
$prefix_list_count = 0
$prefix_list_address_count = 0
$policy_statement_count = 0
$policy_statement_term_count = 0
$interface_count = 0
$vrrp_group_count = 0


# Read/process configuration into array objects
filein.each_line do |line|
  linecount += 1
  line = line.split
  line.map! { |x| x.to_sym}
  case line.at(1)

    #  When line defines an interface take this action
    # this will parse all interface/unit definitions into
    # array $h_interfaces
    when :interfaces
      process_interfaces line

    # When line defines firewall take this action
    # this will parse all firewall definitions into
    # array $h_filters (ipv4 terms) or $h_filters6 (ipv6 terms)
    when :firewall
      process_firewall line

    # When line defines policy-options take this action
    # This will parse policy-options.  Specifically looking for
    # prefix-lists and will store those in $h_prefixlists
    when :'policy-options'
      process_policy_options line

    ### All other definition types aare not yet supported so skip
    else
      next
  end
end

# Close the input (juniper) config file
filein.close

# Create FG policy & objects
fgconfig = String.new    ### this should never be commented out

fgconfig += create_address_objects unless $opts[:skipaddresses]
fgconfig += create_service_objects unless $opts[:skipservices]
fgconfig += create_policy(:ipv4_input_filter) if $opts[:v4inputfilters]
fgconfig += create_policy(:ipv4_output_filter) if $opts[:v4outputfilters]
fgconfig += create_policy(:ipv6_input_filter) if $opts[:v6inputfilters]
fgconfig += create_policy(:ipv6_output_filter) if $opts[:v6outputfilters]
# fgconfig += create_fginterfaces

# Write configuration to output file
fileout = File.open $opts[:fgout], 'w'
fileout.write fgconfig
fileout.close


########################
#### STDOUT Outputs
########################

###
### Pretty print filter hashes
###
pp $h_filters if $opts[:v4filterprint]
pp $h_filters6 if $opts[:v6filterprint]

# ### Print list of each filter (optional all filters or used filters)
# if $opts[:v4filterprint] == 'all' || 'allin' || 'allout'
#    $h_filters.each_key do |x|
#      p x
#    end
# elsif $opts[:v4filterprint]== 'used' || 'usedin' || 'usedout'
#   $h_interfaces.each_key do |int|
#     $h_interfaces[int].each_key do |sub|
#       p $h_interfaces[int][sub][:ipv4_input_filter]
#       p $h_interfaces[int][sub][:ipv4_output_filter]
#     end
#   end
#  end
#  if $opts[:v6filterprint] == 'all' || 'allin' || 'allout'
#    $h_filters6.each_key do |x|
#      p x
#    end
#  end
# pp $h_interfaces if $opts[:interfaceprint]

# Saved for future use if JSON needed
# puts $h_filters.to_json
# JSON.pretty_generate($h_filters).gsub(":", " =>")

unless $opts[:nostats]
  p ''
  p '############ Stats ###############'
  p "Total Lines Procssed............................. #{linecount}"
  p "Total IPv4 Filters............................... #{$h_filters.size}"
  p "  -Total IPv4 Terms...............................#{$ipv4_term_count}"
  p "     -Total with source-address...................#{$ipv4_term_source_address}"
  p "     -Total with source-port......................#{$ipv4_term_source_port}"
  p "     -Total with destination-address..............#{$ipv4_term_destination_address}"
  p "     -Total with destination-port.................#{$ipv4_term_destination_port}"
  p "     -Total with dscp source......................#{$ipv4_term_dscp}"
  p "     -Total with fowarding-class source...........#{$ipv4_term_forwarding_class}"
  p "Total IPv6 Filters............................... #{$h_filters6.size}"
  p "  -Total IPv6 Terms...............................#{$ipv6_term_count}"
  p "     -Total with source-address...................#{$ipv6_term_source_address}"
  p "     -Total with source-port......................#{$ipv6_term_source_port}"
  p "     -Total with destination-address..............#{$ipv6_term_destination_address}"
  p "     -Total with destination-port.................#{$ipv6_term_destination_port}"
  p "     -Total with dscp source......................#{$ipv6_term_dscp}"
  p "     -Total with forwarding-class source..........#{$ipv6_term_forwarding_class}"
  p "Total Prefix Lists................................#{$prefix_list_count}"
  p "  -Total Addresses in Prefix Lists................#{$prefix_list_address_count}"
  p "Total Policy-Statement Filters....................#{$policy_statement_count}"
  p "  -Total Policy-Statement Terms...................#{$policy_statement_term_count}"
  p "Total Interfaces..................................#{$interface_count}"
  p "  -Total VRRP Groups..............................#{$vrrp_group_count}"
  p "  -Total Used IPv4 Input Filters..................#{$ipv4_uniq_inputfilter_count.uniq.count}"
  p "  -Total Used IPv4 Output Filters.................#{$ipv4_uniq_outputfilter_count.uniq.count}"
  p "  -Total Used IPv6 Input Filters..................#{$ipv6_uniq_inputfilter_count.uniq.count}"
  p "  -Total Used IPv6 Output Filters.................#{$ipv6_uniq_outputfilter_count.uniq.count}"
end
