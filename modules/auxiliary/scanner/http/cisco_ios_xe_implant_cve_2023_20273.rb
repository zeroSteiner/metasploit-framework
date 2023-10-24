##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Cisco
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco IOS XE Implant Detection',
        'Description' => %q{
          This module will detect the implant that was commonly deployed by threat actors after successfully exploiting
          CVE-2023-20273.
        },
        'Author'	=> [ 'Spencer McIntyre' ],
        'License'	=> MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/' ],
          [ 'URL', 'https://github.com/fox-it/cisco-ios-xe-implant-detection' ]
        ],
        'DisclosureDate' => '2023-10-16',
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to the web application', '/'])
      ]
    )
  end

  def is_target_ios_xe?
    res = send_request_cgi('uri' => normalize_uri(target_uri, 'webui'))
    return false unless res&.code == 200
    return false unless res.headers['Server'] =~ /^openresty/i

    return res.body.include?('Cisco Systems')
  end

  def is_target_infected?
    res = send_request_cgi('uri' => normalize_uri('%25'))
    return res&.code == 404
  end

  def run_host(_ip)
    unless is_target_ios_xe?
      vprint_status("#{peer} - The target is not running IOS XE.")
      return
    end

    unless is_target_infected?
      print_status("#{peer} - The target is not infected.")
      return
    end

    print_error("#{peer} - The target is infected.")
  end
end
