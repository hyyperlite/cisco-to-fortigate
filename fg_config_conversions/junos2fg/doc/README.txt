Description:
junos2fg.rb v0.2 parses a Juniper JunOS 11.4R7.5 configuration file (in format of "display set") and provides an output file with
FortiOS 5.4.1 address objects, service objects and policies.

Limitations:
junos2fg.rb v0.2 oes not currently support VPLS policies, dscp acl rules, forwarding-class based rules, or general
traffic shaping QoS/CoS. Currently, for inbound policies there is no interface mapping functionality.


Execution:
ruby junos2fg.rb <options>

Options:
  # junosin: Source JunOS configuration file (type: string) (default: ./junos.conf)
  --junosin <path/file> OR -i <path/file>

  # fgout: Output file containing FG configuration for processed options (type: string) (default: ./junos2fg.out)
  --fgout <path/file> OR -o <path/file>

  # verbose: Additional detail to STDOUT (type: boolean) (default: false)
  --verbose OR -v:

  # debug: Full detail to STDOUT (type: boolean) (default: false)
  --debug, -d

  # nostats: Do not print statistics to STDOUT (type: boolean) (default: false)
  --nostats, -n

  # servicecategory: All services will be assigned to this service category
  # (type: string) (default: "converted)
  --servicecategory

  # v4inputfilters: Create FG configuration for IPv4 Input Filters (type: boolean) (default: false)
   --v4inputflters

  # v4outputfilters Create FG configuration for IPv4 Output Filters (type: boolean) (default: false)
  --v4outputfilters

  # v6inputfilters: Create FG configuration for IPv6 Input Filters (type: boolean) (default: false)
  --v6inputfilters

  # v6outputfilters: Create FG configuration for IPv6 Output Filters (type: boolean) (default: false)
  --v6outputfilters

  # skipaddresses: Do not output FG address objects (type: boolean) (default: false)
  --skipaddresses

  # Do not output FG service objects (type: boolean) (default: false)
  --skipservices

  # map2sub: For Egress JunOS filters (if being processed) if the destination address is not specified or is 'any'
  # identify the subnet of the egress interface and use this subnet as the destination address instead of 'any'
  # (type: boolean) (default: false)
  --map2sub

  # interfacemapout: Provide a test file list of junos interface to fortigate interface mappings.  This text file
  # can contain mapping to fg zones also.  Many junos interfaces can be mapped to a single FG interface or zone.
  # When supplied, only junos interfaces in the file will have corresponding FG policies created all other interfaces
  # in the source juniper configuration file will be skipped.  When this command is not used all interfaces are processed
  # and output filters/fg policies associated to all interfaces is output.
  # text file should be of following format

    junos-interface mapped-fg-interface
    junos-interface2 mapped-fg-interface
    junos-interface3 mappped-fg-interface3

  # (type: string) (default: not enabled)
  --interfacemapout </path/to/mapfile>

