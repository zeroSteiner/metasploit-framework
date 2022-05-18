##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '',
        'Description' => %q{
        },
        'References' => [
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          # TODO: check on adding an AddUser action
          ['AddComputer', { 'Description' => 'Add a new Computer' }]
        ],
        'DefaultAction' => 'AddComputer',
        'DefaultOptions' => {
          'SSL' => true,
        },
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options([
      Opt::RPORT(636), # SSL/TLS
    ])
  end

  def run
    print_status("#{peer} Connecting...")
    ldap_connect do |ldap|
      fail_with(Failure::NoAccess, 'Failed to bind to the remote server.') unless ldap.get_operation_result.result == 0

      discover_base_dn(ldap)
    end
  end
end
