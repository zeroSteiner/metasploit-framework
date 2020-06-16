##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Secretsdump',
      'Description' => '',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE
    )
  end

  def run_host(ip)
    print_status("Connecting to the server...")
    connect(versions: [2, 1])

    print_status("Authenticating to #{smbhost} as user '#{splitname(datastore['SMBUser'])}'...")
    smb_login

    simple.connect("\\\\#{ip}\\IPC$")
    handle = dcerpc_handle('367abb81-9844-35f1-ad32-98f038001003', '2.0', 'ncacn_np', ["\\svcctl"])
    vprint_status("Binding to #{handle} ...")
    dcerpc_bind(handle)
    vprint_status("Bound to #{handle} ...")
    vprint_status("Obtaining a service manager handle...")

    svc_client = Rex::Proto::DCERPC::SVCCTL::Client.new(dcerpc)
    scm_handle, scm_status = svc_client.openscmanagerw(ip)

    if scm_status == ERROR_ACCESS_DENIED
      print_error("ERROR_ACCESS_DENIED opening the Service Manager")
    end

    return unless scm_handle
    svc_handle = svc_client.openservicew(scm_handle, 'RemoteRegistry')

    # QUERY_SERVICE_STATUS appears to be wrong, it's defined as 5, but should be 6 per:
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/cf94d915-b4e1-40e5-872b-a9cb3ad09b46
    #
    # Need to update the return to properly pares https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/4e91ff36-ab5f-49ed-a43d-a308e72b0b3c
    case svc_client.queryservice(svc_handle)
      when 1
        vprint_status('The RemoteRegistry service is running')
      when 2
        vprint_status('The RemoteRegistry service is stopped')
    end

  end
end
