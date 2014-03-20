##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Host Information Enumeration via NTLM Authentication',
      'Description' => %q{
          This module makes requests to resources on the target server in
        an attempt to find resources which permit NTLM authentication. For
        resources which permit NTLM authentication, a blank NTLM type 1 message
        is sent to enumerate a a type 2 message from the target server. The type
        2 message is then parsed for information such as the Active Directory
        domain and NetBIOS name.  A single URI can be specified with TARGET_URI
        or a file or URIs can be specified with TARGET_URIS_FILE (default).
      },
      'Author'      => 'Brandon Knight',
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        OptString.new('TARGET_URI', [ false, "Single target URI", nil]),
        OptPath.new('TARGET_URIS_FILE', [ false, "Path to list of URIs to request", File.join(Msf::Config.data_directory, "wordlists", "http_owa_common.txt")]),
      ], self.class)
  end

  def run_host(ip)
    if datastore['TARGET_URI']
      test_path = normalize_uri(datastore['TARGET_URI'])
      result = check_url(test_path)
      handle_result(test_path, result) if result
      return
    elsif datastore['TARGET_URIS_FILE']
      File.open(datastore['TARGET_URIS_FILE'], 'rb').each_line do |line|
        test_uri = line.chomp
        test_path = normalize_uri(test_uri)
        result = check_url(test_path)
        if result
          handle_result(test_path, result)
          return
        end
      end
    else
      fail_with "Either TARGET_URI or TARGET_URIS_FILE must be specified."
    end
  end

  def handle_result(path, result)
    message = "Enumerated info on #{peer}#{path} - "
    message << "(name:#{result[:nb_name]}) "
    message << "(domain:#{result[:nb_domain]}) "
    message << "(domain_fqdn:#{result[:dns_domain]}) "
    message << "(server_fqdn:#{result[:dns_server]})"
    print_good(message)
    report_note(
      :host  => rhost,
      :port  => rport,
      :proto => 'tcp',
      :sname => (ssl ? 'https' : 'http'),
      :ntype => 'ntlm.enumeration.info',
      :data  => {
        :uri        => path,
        :SMBName    => result[:nb_name],
        :SMBDomain  => result[:nb_domain],
        :FQDNDomain => result[:dns_domain],
        :FQDNName   => result[:dns_server]
      },
      :update => :unique_data
    )
  end

  def check_url(test_uri)
    begin

      vprint_status("Checking #{peer} URL #{test_uri}")
      res = send_request_cgi({
        'encode'   => true,
        'uri'      => "#{test_uri}",
        'method'   => 'GET',
        'headers'  =>  { "Authorization" => "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="}
      })
    rescue OpenSSL::SSL::SSLError
      vprint_error("#{peer} - SSL error")
      return
    rescue Errno::ENOPROTOOPT, Errno::ECONNRESET, ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
      vprint_error("#{peer} - Unable to Connect")
      return
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("#{peer} - Timeout error")
      return
    end

    return if res.nil?

    vprint_status("Status: #{res.code}")
    if res and res.code == 401 and res['WWW-Authenticate'].match(/^NTLM/i)
      hash = res['WWW-Authenticate'].split('NTLM ')[1]
      # Parse out the NTLM and just get the Target Information Data
      target = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(hash))[:target_info].value()
      # Retrieve Domain name subblock info
      nb_domain = parse_ntlm_info(target, "\x02\x00", 0)
      # Retrieve Server name subblock info
      nb_name = parse_ntlm_info(target, "\x01\x00", nb_domain[:new_offset])
      # Retrieve DNS domain name subblock info
      dns_domain = parse_ntlm_info(target, "\x04\x00", nb_name[:new_offset])
      # Retrieve DNS server name subblock info
      dns_server = parse_ntlm_info(target, "\x03\x00", dns_domain[:new_offset])

      return {
        :nb_name    => nb_name[:message],
        :nb_domain  => nb_domain[:message],
        :dns_domain => dns_domain[:message],
        :dns_server => dns_server[:message]
      }
    end
  end

  def parse_ntlm_info(message,pattern,offset)
    name_index = message.index(pattern,offset)
    offset = name_index.to_i
    size = message[offset+2].unpack('C').first
    return {
      :message=>message[offset+3,size].gsub(/\0/,''),
      :new_offset => offset + size
    }
  end

end
