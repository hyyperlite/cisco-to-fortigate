require 'trollop'
require 'pp'
require 'json'

#### Handle Input Options
opts = Trollop::options {
  version 'juniper-reader v0.1 '
  banner <<-EOS
Usage:
    jsfa [options] <filenames>
where [options] are:
  EOS

  opt :configfile, 'Configuration File', :type => String
}
##################################################
### Methods
##################################################
def process_firewall fw
  ## Temp Testing
  # p "1: #{fw.at(1)}"
  # p "2: #{fw.at(2)}"
  # p "3: #{fw.at(3)}"
  # p "4: #{fw.at(4)}"
  # p "5: #{fw.at(5)}"
  # p "6: #{fw.at(6)}"
  # p "7: #{fw.at(7)}"
  # p "8: #{fw.at(8)}"
  # p "9: #{fw.at(9)}"
  # p "10: #{fw.at(10)}"

  #### Make sure the record is of firewall sub-type family
  if fw.at(2) == :family
    ### Make sure the record is and ipv4 firewall filter
    if fw.at(3) == :inet  && fw.at(4) == :filter
        ### Ensure that a "term" has been specified then create the first key "filter"
        if fw.at(6) == :term
          $h_filters[fw.at(5)] = {} if $h_filters.has_key?(fw.at(5)) == false

          ### Add the terms to the filter hashes and create the term detail hash structure
          if $h_filters[fw.at(5)].has_key?(fw.at(7)) == false
            $h_filters[fw.at(5)][fw.at(7)] = {:source => Hash.new, :action => nil, :'forwarding-class' => nil, :'loss-priority' => nil, :policer => nil}
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
        $h_filters6[fw.at(5)] = {} if $h_filters6.has_key?(fw.at(5)) == false
        ### Add the terms to the filter hashes and create the term detail hash structure
        if $h_filters6[fw.at(5)].has_key?(fw.at(7)) == false
          $h_filters6[fw.at(5)][fw.at(7)] = {:source => Hash.new, :action => nil, :'forwarding-class' => nil, :'loss-priority' => nil, :policer => nil}
          $ipv6_term_count += 1
        end

        ### Populate term details (sources (and source type), action, forwarding-classs, loss-priority)
        case fw.at(8)
          ### source detail
          when :from
            $h_filters6[fw.at(5)][fw.at(7)][:source][fw.at(10)] = fw.at(9)
            $ipv6_term_source_address += 1 if fw.at(9) == :'source-address'
            $ipv6_term_source_port += 1 if fw.at(9) == :'source-port'
            $ipv6_term_destination_address += 1 if fw.at(9) == :'destination-address'
            $ipv6_term_destination_port += 1 if fw.at(9) == :'destination-port'

          ### action/forwarding-class/loss-priority
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

    elsif fw.at(3) == "vpls" && fw.at(4) == "filter"
      p "this is a vpls filter"
    else
      return
    end
  elsif fw.at(2) == "policer"
    #p "policiers are unsupported"
  else
    #p "unsupported firewall option"
  end
end

def process_policy_options po
  if po.at(2) == :'prefix-list'
    if $h_prefix_lists.has_key?(po.at(3)) == false
      $h_prefix_lists[po.at(3)] = Array.new
      $prefix_list_count += 1
    end

  $h_prefix_lists[po.at(3)] << po.at(4)
  $prefix_list_address_count += 1

  elsif po.at(2) == :'policy-statement'
    if $h_policy_statements.has_key?(po.at(3)) == false
      $h_policy_statements[po.at(3)] = Hash.new
      $policy_statement_count += 1
    end
    if $h_policy_statements[po.at(3)].has_key?(po.at(5)) == false
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
      else
        p "policy-statement: config-type not supported, skipping: #{po.at(6)}"
    end
  else
    p "policy-option: config-type not supported, skipping: #{po.at(2)}"
  end
end

def process_interfaces int
  return if int.at(3) != :unit

  if $h_interfaces.has_key?(int.at(2)) == false
    $h_interfaces[int.at(2)] = Hash.new
  end

  if $h_interfaces[int.at(2)].has_key?(int.at(4)) == false
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
  $h_interfaces[int.at(2)][int.at(4)][:ipv4_input_filter] = int.at(9) if int.at(6) == :inet && int.at(7) == :filter\
   && int.at(8) == :input
  $h_interfaces[int.at(2)][int.at(4)][:ipv4_output_filter] = int.at(9) if int.at(6) == :inet && int.at(7) == :filter\
   && int.at(8) == :output
  $h_interfaces[int.at(2)][int.at(4)][:ipv6_input_filter] = int.at(9) if int.at(6) == :inet6 && int.at(7) == :filter\
   && int.at(8) == :input
  $h_interfaces[int.at(2)][int.at(4)][:ipv6_output_filter] = int.at(9) if int.at(6) == :inet6 && int.at(7) == :filter\
   && int.at(8) == :output


  ### VRRP Detail
  if int.at(9) == :'vrrp-group'
    if $h_interfaces[int.at(2)][int.at(4)][:vrrp].has_key?(int.at(10)) == false
      $h_interfaces[int.at(2)][int.at(4)][:vrrp][int.at(10)] = {\
      :'virtual-address' => nil,\
      :'intf-address' => nil,\
      :priority => nil,\
      :'advertise-interval' => nil,\
      :preempt => nil,\
      :'accept-data' => nil,\
      :'authentication-type' => nil,\
      :'authentication-key' => nil }
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

#########################################
### Main
#########################################
### open config file for reading
f = File.open opts[:configfile], "r"

### Limit execution cycles during testing
#MAX_COUNT = 100000
MAX_COUNT = 100000
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
$prefix_list_count = 0
$prefix_list_address_count = 0
$policy_statement_count = 0
$policy_statement_term_count = 0
$interface_count = 0


f.each_line do |line|
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
    when :"policy-options"
      process_policy_options line

    ### All other definition types aare not yet supported so skip
    else
      break if linecount >= MAX_COUNT
      next
  end
  break if linecount >= MAX_COUNT
end

f.close

#pp $h_filters
#pp $h_filters6
#pp $h_prefix_lists
#pp $h_policy_statements
pp $h_interfaces
#puts $h_filters.to_json
#JSON.pretty_generate($h_filters).gsub(":", " =>")
p ""
p "############ Stats ###############"
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
