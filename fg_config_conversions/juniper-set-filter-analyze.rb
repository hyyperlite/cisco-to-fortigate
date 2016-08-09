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
  #### Make sure the record is of firewall sub-type family
  if fw.at(2) == :family

    ### Make sure the record is and ipv4 firewall filter
    if fw.at(3) == :inet  && fw.at(4) == :filter

        ### Ensure that a "term" has been specified then create the first key "filter"
        if fw.at(6) == :term
          $h_filters[fw.at(5)] = {} if $h_filters.has_key?(fw.at(5)) == false
          $ipv4_term_count += 1
          ### Add the terms to the filter hashes and create the term detail hash structure
          if $h_filters[fw.at(5)].has_key?(fw.at(7)) == false
            $h_filters[fw.at(5)][fw.at(7)] = {:source => Hash.new, :action => nil, :'forwarding-class' => nil, :'loss-priority' => nil, :policer => nil}
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
                  p "action-type not supported, skipping: #{fw.at(9)} --> #{fw.at(10)}"
                end
            ### other filter object reference
            when :filter
              $h_filters[fw.at(5)][fw.at(7)][:source][fw.at(9)] = :filter
          end
        end

    ### IPv6 FW filter processing
    elsif fw.at(3) == "inet6" && fw.at(4) == "filter"
        ### Ensure that a "term" has been specified then create the first key "filter"
        if fw.at(6) == :term
          $h_filters6[fw.at(5)] = {} if $h_filters6.has_key?(fw.at(5)) == false
          $ipv6_term_count += 1
          ### Add the terms to the filter hashes and create the term detail hash structure
          if $h_filters6[fw.at(5)].has_key?(fw.at(7)) == false
            $h_filters6[fw.at(5)][fw.at(7)] = {:source => Hash.new, :action => nil, :'forwarding-class' => nil, :'loss-priority' => nil, :policer => nil}
          end

          ### Populate term details (sources (and source type), action, forwarding-classs, loss-priority)
          case fw.at(8)
            ### source detail
            when :from
              $h_filters6[fw.at(5)][fw.at(7)][:source][fw.at(10)] = fw.at(9)
              $ipv4_term_source_address += 1 if fw.at(9) == :'source-address'
              $ipv4_term_source_port += 1 if fw.at(9) == :'source-port'
              $ipv4_term_destination_address += 1 if fw.at(9) == :'destination-address'
              $ipv4_term_destination_port += 1 if fw.at(9) == :'destination-port'

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
                  p "action-type not supported, skipping: #{fw.at(9)} --> #{fw.at(10)}"
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

#########################################
### Main Execution
#########################################
### open oonfig file for reading
f = File.open opts[:configfile], "r"

### Limit execution cycles during testing
#MAX_COUNT = 100000
MAX_COUNT = 100000

linecount = 0
### Create global hprimary data hashes
$h_interfaces = Hash.new
$h_filters = Hash.new
$h_filters6 = Hash.new

### Create counter vars
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


f.each_line do |line|
  linecount += 1
  line = line.split
  line.map! { |x| x.to_sym}
  case line.at(1)
###  When line defines an interface take this action
    when :interfaces
      next
### When line defines firewall take this action
    when :firewall
      process_firewall line
### When line defines policy-options take this action
    when :"policy-options"
      next
### All other definition types aare not yet supported so skip
    else
      break if linecount >= MAX_COUNT
      next
  end
  break if linecount >= MAX_COUNT
end

f.close

#pp $h_filters
pp $h_filters6
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
