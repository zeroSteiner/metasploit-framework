##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DHCPServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'DHCP Server',
      'Description' => %q{
        This module provides a DHCP service
      },
      'Author' => [ 'scriptjunkie', 'apconole@yahoo.com' ],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Service', 'Description' => 'Run DHCP server' ]
      ],
      'PassiveActions' => [
        'Service'
      ],
      'DefaultAction' => 'Service'
    )
  end

  def run
    print_status("Starting DHCP server...")
    start_service

    # Wait for finish..
    while @dhcp.thread.alive?
      select(nil, nil, nil, 2)
    end

    print_status("Stopping DHCP server...")
    stop_service
  end
end
