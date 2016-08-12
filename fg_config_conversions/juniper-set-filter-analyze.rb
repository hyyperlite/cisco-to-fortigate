require 'trollop'
require 'pp'
require 'json'
require 'set'

#### Handle Input Options
opts = Trollop::options {
  version 'juniper-reader v0.1 '
  banner <<-EOS
Usage:
    jsfa [options] <filenames>+
where [options] are:
EOS

  opt :junosin, 'Configuration File', :type => :string, :default => 'juniper.conf', :short => '-i'
  opt :fgout, 'Configuration File', :type => :string, :default => 'output.conf', :short => '-o'
  opt :debug, 'Turn on extended messaging', :short => '-d'
  opt :nostats, 'Disable statistical output', :short => '-n'
}
##################################################
### Methods
##################################################
def process_firewall(fw)

  #### Make sure the record is of firewall sub-type family
  if fw.at(2) == :family
    ### Make sure the record is and ipv4 firewall filter
    if fw.at(3) == :inet  && fw.at(4) == :filter
        ### Ensure that a "term" has been specified then create the first key "filter"
        if fw.at(6) == :term
          $h_filters[fw.at(5)] = {} unless $h_filters.has_key?(fw.at(5))

          ### Add the terms to the filter hashes and create the term detail hash structure
          unless $h_filters[fw.at(5)].has_key?(fw.at(7))
            $h_filters[fw.at(5)][fw.at(7)] = {\
            :source => Hash.new,\
            :action => nil,\
            :'forwarding-class' => nil,\
            :'loss-priority' => nil,\
            :policer => nil}

            ### count the number of total terms processed
            $ipv4_term_count += 1
          end

          ### Populate term details (sources (and source type), action, forwarding-classs, loss-priority)
          case fw.at(8)
            ### source detail
            when :from
              $h_filters[fw.at(5)][fw.at(7)][:source][fw.at(10)] = fw.at(9)
              $ipv4_term_source_address += 1 if fw.at(9) == :'source-address'
              $ipv4_term_source_port += 1 if fw.at(9) == :'source-port'
              $ipv4_term_destination_address += 1 if fw.at(9) == :'destination-address'
              $ipv4_term_destination_port += 1 if fw.at(9) == :'destination-port'

            ### action/forwarding-class/loss-priority
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
                  p "ipv4 filter: action-type not supported, skipping: #{fw.at(9)} --> #{fw.at(10)}" unless fw.at(9) == :count
              end
            ### other filter object reference
            when :filter
              $h_filters[fw.at(5)][fw.at(7)][:source][fw.at(9)] = :filter
          end
        end

    ### IPv6 FW filter processing
    elsif fw.at(3) == :inet6 && fw.at(4) == :filter

      ### Ensure that a "term" has been specified then create the first key "filter"
      if fw.at(6) == :term
        $h_filters6[fw.at(5)] = {} unless $h_filters6.has_key?(fw.at(5))

        ### Add the terms to the filter hashes and create the term detail hash structure
        unless $h_filters6[fw.at(5)].has_key?(fw.at(7))
          $h_filters6[fw.at(5)][fw.at(7)] = {:source => Hash.new, :action => nil, :'forwarding-class' => nil, :'loss-priority' => nil, :policer => nil}
          $ipv6_term_count += 1
        end

        ### Populate term details, sources and source type as hash entries to $h_entries
        case fw.at(8)

          ### source detail
          when :from
            $h_filters6[fw.at(5)][fw.at(7)][:source][fw.at(10)] = fw.at(9)
            $ipv6_term_source_address += 1 if fw.at(9) == :'source-address'
            $ipv6_term_source_port += 1 if fw.at(9) == :'source-port'
            $ipv6_term_destination_address += 1 if fw.at(9) == :'destination-address'
            $ipv6_term_destination_port += 1 if fw.at(9) == :'destination-port'

          ### add action/forwarding-class/loss-priority/etc options to $h_filter entries if they exist
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
                p "ipv6 filter: action-type not supported, skipping: #{fw.at(9)} --> #{fw.at(10)}" unless fw.at(9) == :count
            end
          ### other filter object reference
          when :filter
            $h_filters6[fw.at(5)][fw.at(7)][:source][fw.at(9)] = :filter
        end
      end

    ### If this is a vpls firewall filter, for now we are noting it in output but taking no action
    ### as vpls isn't easily translatable to FortiGate
    elsif fw.at(3) == :vpls && fw.at(4) == :filter
      p "firewall: no action taken on vpls filter (yet)"
    else
      return
    end

  ### If this is not a firewall filter and is instead a policer definition
  elsif fw.at(2) == "policer"
    p "firewall: no action taken on policiers (yet)"
  else
    p "firewall: unsupported firewall option, #{fw.at(2)}"
  end

end

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

    ### Populate policy-statement term details
    case po.at(6)
      ### source detail
      when :from
        $h_policy_statements[po.at(3)][po.at(5)][:source][po.at(8)] = po.at(7)

      ### actions
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
             p "policy-statement: action-type not supported, skipping: #{po.at(7)} --> #{po.at(8)}"
        end
    end

  else
    p "policy-option: type not supported, skipping: #{po.at(2)}"
  end
end

def process_interfaces(int)
  return if int.at(3) != :unit

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

  ### IP address info
  if (int.at(6) == :inet && int.at(7) == :address) && (int.at(9) == :primary || int.at(9) == nil)
    $h_interfaces[int.at(2)][int.at(4)][:'address_v4_primary'] = int.at(8)
  end
  if (int.at(6) == :inet6 && int.at(7) == :address) && (int.at(9) == :primary || int.at(9) == nil)
    $h_interfaces[int.at(2)][int.at(4)][:'address_v6_primary'] = int.at(8)
  end

  ### Set Interface Description
  $h_interfaces[int.at(2)][int.at(4)][:description] = int.at(6) if int.at(5) == :description

  ### Set vlan-id
  $h_interfaces[int.at(2)][int.at(4)][:vlan] = int.at(6) if int.at(5) == :'vlan-id'

  ### Set input/output filters
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

  ### VRRP Detail
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

def create_fgpolicy_address_objects
  a_addresses = Array.new
  a_prefix_lists = Array.new
  config = ''

  $h_filters.each do |filtername,filterarray|
    $h_filters[filtername].each do |termname,termarray|
      $h_filters[filtername][termname][:source].each do |sourcename, sourcetype|
        if sourcetype == :'source-address' || sourcetype == :'destination-address'

          # Adding all to new hash in order to remove duplicates
          a_addresses << sourcename
        end
        if sourcetype == :'source-prefix-list' || sourcetype == :'destination-prefix-list' || sourcetype == :'prefix-list'
          a_prefix_lists << sourcename
          a_prefix_lists.uniq.each do |prefixlist|
            $h_prefix_lists[prefixlist].each do |prefixadds|
              a_addresses << prefixadds
            end
          end
        end
      end
    end
  end

  ### create a fg config entry for each uniq address identified
  a_addresses.uniq.each do |x|

    fgaddress = <<-EOS
config fireawall address
  edit #{x}
    set type subnet
    set subnet #{x}
  next
end
  EOS

    ### add each output from Herdoc above to config var (will pass this back to main)
    config += fgaddress
  end

  $h_prefix_lists.each do |prefixlist, prefixadds|

    ### convert array to string usable in addrgroup config
    adds = String.new
    prefixadds.each {|x| adds += "#{x.to_s} "}

    fggroups = <<-EOS
config firewall addrgroup
  edit #{prefixlist}
    set member #{adds}
  next
end
    EOS

    config += fggroups
  end

  ### return this pieces of FG config to main for addtional methods to add to it
  return config

end

def create_fgpolicy_service_objects


  config = String.new               ### initialize the local (to this method) config container var
  fgservice = String.new            ### initialize the item by item config var
  service_tracker = Set.new             ### create set for tracking if servie already has been created

  ### Open external files with data for mapping protocol port numbers
  ip = File.open 'ip_protocol_nums.txt', 'r'
  tcpudp = File.open 'tcp-udp_ports.txt', 'r'
  icmp = File.open 'icmp_type_codes.txt', 'r'

  ### Initialize hashes for stroing the protocol/port number information from files
  h_ip = Hash.new
  h_tcpudp = Hash.new
  h_icmp = Hash.new

  ### import the ip protocol number info from file to h_ip hash
  ip.each_line do |x|
    num, name = x.split
    h_ip[num] = name
  end

  ### reverse the keys and values
  h_ip = h_ip.invert

  ### import the tcp/dump port number info from file to h_tcpudp hash
  tcpudp.each_line do |x|
    num, name = x.split
    h_tcpudp[num] = name
  end

  ### reverse the keys and values
  h_tcpudp = h_tcpudp.invert

  ### import the icmp type code detail from file to the h_icmp hash
  icmp.each_line do |x|
    num, name = x.split
    h_icmp[num] = name
  end

  ### reverse the keys and values
  h_icmp = h_icmp.invert

  ### close the protocol info files
  ip.close
  tcpudp.close
  icmp.close

  ### Create a new service category in the local fg config file to assign all created services to
  config = <<-EOS
config firewall service category
  edit Comcast
end

EOS

  $h_filters.each do |filtername,filterarray|
    $h_filters[filtername].each do |termname,termarray|
      $h_filters[filtername][termname][:source].each do |sourcename, sourcetype|

        ### Use sourcetype to identify service definitions then modify those as needed to
        ### convert for use in FG config
        case sourcetype.to_s   # we will be matching against strings and output to string so need to chg from symbol
          when *%w[destination-port source-port port]

            ### matching anythng that is all digits or digits with a single dash
            ### the just digits indicates a single port number while with a dash is a range
            ### anything that does not match these will be processed in subsequent case
            ### as we'll need to map those from words "http, ftp, etc" to port numbers
            if /^(\d+)$/ =~ sourcename || /^(\d+[-]\d+)$/ =~ sourcename

              lowport, highport = ''
              lowport, highport = sourcename.to_s.split('-')

              highport = lowport if !highport
              #p "lowport #{lowport}, highport #{highport}"

              tcp, udp, icmp = nil
              if $h_filters[filtername][termname][:source].has_key?(:tcp)
                tcp = 1
              end

              if $h_filters[filtername][termname][:source].has_key?(:udp)
                udp = 1
              end

              if $h_filters[filtername][termname][:source].has_key?(:icmp)
                icmp = 1
              end
             if !tcp && !udp && !icmp
               tcp = 1
               udp = 1
             end

            if (tcp == 1 && !service_tracker.include?("#{sourcename}-tcp") && sourcetype != :'source-port')

fgservice = ''
fgservice = <<-EOS
config firewall service custom
  edit #{sourcename}-tcp
    set tcp-portrange #{lowport} #{highport}
    set category Comcast
    set comment "created by hyyperconverter"
  next
end
EOS

              ### add each output from Heredocs above to config var (will pass this back to main)
              config += fgservice
              service_tracker.add("#{sourcename}-tcp")
            end

            if (udp == 1 && !service_tracker.include?("#{sourcename}-tcp") && sourcetype != :'source-port')

fgservice = ''
fgservice = <<-EOS
config firewall service custom
  edit #{sourcename}-udp
    set udp-portgrange #{lowport} #{highport}
    set category Comcast
    set comment "created by hyyperconverter"
  next
end
EOS

              ### add each output from Heredocs above to config var (will pass this back to main)
              config += fgservice
              service_tracker.add("#{sourcename}-udp")

            end

              if (tcp == 1 && !service_tracker.include?("#{sourcename}-tcp_source") && sourcetype == :'source-port')

                fgservice = ''
                fgservice = <<-EOS
config firewall service custom
  edit #{sourcename}-tcp_source
    set tcp-portgrange 1 65535 #{lowport} #{highport}
    set category Comcast
    set comment "created by hyyperconverter"
  next
end
EOS

                ### add each output from Heredocs above to config var (will pass this back to main)
                config += fgservice
                service_tracker.add("#{sourcename}-tcp_source")

              end

              if (udp == 1 && !service_tracker.include?("#{sourcename}-udp_source") && sourcetype == :'source-port')

                fgservice = ''
                fgservice = <<-EOS
config firewall service custom
  edit #{sourcename}-udp_source
    set udp-portgrange 1 65535 #{lowport} #{highport}
    set category Comcast
    set comment "created by hyyperconverter"
  next
end
EOS

                ### add each output from Heredocs above to config var (will pass this back to main)
                config += fgservice
                service_tracker.add("#{sourcename}-udp_source")

              end

            else
              ### Get port matching sourcename from h_tcpudp service/port mapping array
#               port = h_tcpudp[sourcename.to_s]
#
#               #p "Sourcename: #{sourcename} --> Port: #{port}"
#               if port == nil
#                 p "Couldn't find a protocol match: Sourcename: #{sourcename} --> Port: #{port}"
#                 next
#               end
#               tcp, udp, icmp = nil
#               if $h_filters[filtername][termname][:source].has_key?(:tcp)
#                 tcp = 1
#               end
#
#               if $h_filters[filtername][termname][:source].has_key?(:udp)
#                 udp = 1
#               end
#
#               if $h_filters[filtername][termname][:source].has_key?(:icmp)
#                 icmp = 1
#               end
#               if !tcp && !udp && !icmp
#                 tcp = 1
#                 udp = 1
#               end
#
#               if (tcp == 1 && !service_tracker.include?("#{sourcename}-tcp") && sourcetype != :'source-port')
#
#                 fgservice = ''
#                 fgservice = <<-EOS
# config firewall service custom
#   edit #{sourcename}_source
#     set tcp-portgrange 1 65535 #{lowport} #{highport}
#     set category Comcast
#     set comment "created by hyyperconverter"
#   next
# end
# EOS
#                 ### add each output from Heredocs above to config var (will pass this back to main)
#                 config += fgservice
#                 service_tracker.add("#{sourcename}")
#
#               end
            end

          when *%w[icmp-type icmp-type-exempt]
            #
          else
            # p "service: service-type not yet supported #{sourcetype}"
        end
      end
    end
  end
  p "service tracker"
  service_tracker.each do |x|
    p x
  end

  ### Return the resulting config to main execution
  return config
end

def create_fgpolicy_rules
 # $h_filters.each_key do |filtername|
 #   $h_filters[filtername].each_key do |termname|
 #
 #   end
 # end
end
#########################################
### Main
#########################################
### open config file for reading
filein = File.open opts[:junosin], 'r'

### Limit execution cycles during testing
MAX_COUNT = 100_000
linecount = 0

### Create global hprimary data hashes
$h_interfaces = Hash.new
$h_filters = Hash.new
$h_filters6 = Hash.new
$h_prefix_lists = Hash.new
$h_policy_statements = Hash.new

### Create counters
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
$ipv6_uniq_inputfilter_count = Array.new
$ipv6_uniq_outputfilter_count = Array.new
$prefix_list_count = 0
$prefix_list_address_count = 0
$policy_statement_count = 0
$policy_statement_term_count = 0
$interface_count = 0
$vrrp_group_count = 0


### Read/process configuration into usable objects
filein.each_line do |line|
  linecount += 1
  line = line.split
  line.map! { |x| x.to_sym}
  case line.at(1)

    ###  When line defines an interface take this action
    when :interfaces
      process_interfaces line

    ### When line defines firewall take this action
    when :firewall
      process_firewall line

    ### When line defines policy-options take this action
    when :'policy-options'
      process_policy_options line

    ### All other definition types aare not yet supported so skip
    else
      break if linecount >= MAX_COUNT
      next
  end
  break if linecount >= MAX_COUNT
end

### Close the input (juniper) config file
filein.close

### Create FG policy & objects
fgconfig = String.new
#fgconfig += create_fgpolicy_address_objects
fgconfig += create_fgpolicy_service_objects
#fgconfig += create_fgpolicy_rules
#create_fgpolicy_rules
#fgconfig += create_fginterfaces

### Write configuration to output file
fileout = File.open opts[:fgout], 'w'
fileout.write fgconfig
fileout.close


########################
#### STDOUT Outputs
########################
#pp $h_filters
#pp $h_filters6
#pp $h_prefix_lists
#pp $h_policy_statements
#pp $h_interfaces
#puts $h_filters.to_json
#JSON.pretty_generate($h_filters).gsub(":", " =>")

unless opts[:nostats]
  p ''
  p '############ Stats ###############'
  p "Total Lines Procssed............................. #{linecount}"
  p "Total IPv4 Filters............................... #{$h_filters.size}"
  p "  -Total IPv4 Terms...............................#{$ipv4_term_count}"
  p "     -Total with source-address...................#{$ipv4_term_source_address}"
  p "     -Total with source-port......................#{$ipv4_term_source_port}"
  p "     -Total with destination-address..............#{$ipv4_term_destination_address}"
  p "     -Total with destination-port.................#{$ipv4_term_destination_port}"
  p "Total IPv6 Filters............................... #{$h_filters6.size}"
  p "  -Total IPv6 Terms...............................#{$ipv6_term_count}"
  p "     -Total with source-address...................#{$ipv6_term_source_address}"
  p "     -Total with source-port......................#{$ipv6_term_source_port}"
  p "     -Total with destination-address..............#{$ipv6_term_destination_address}"
  p "     -Total with destination-port.................#{$ipv6_term_destination_port}"
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
