##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule < Msf::Auxiliary

  include Exploit::Remote::DNS::Common
  include Exploit::Remote::SocketServer

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

    register_advanced_options(
      [
        OptString.new('PrinterName', [true, 'The printer name', Faker::Device.model_name])
      ])
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    begin
      start_mdns_service
      service.wait
    rescue Rex::BindFailed => e
      print_error "Failed to bind to port #{datastore['RPORT']}: #{e.message}"
    end
  end

  # mDNS code below

  def start_mdns_service
    begin
      comm = _determine_server_comm(bindhost)
      self.service = Rex::ServiceManager.start(
        Rex::Proto::MDNS::Server,
        bindhost,
        5353,
        false,
        nil,
        comm,
        {'Msf' => framework, 'MsfExploit' => self}
      )

      self.service.dispatch_request_proc = Proc.new do |cli, data|
        on_dispatch_mdns_request(cli, data)
      end
      self.service.send_response_proc = Proc.new do |cli, data|
        on_send_mdns_response(cli, data)
      end
    rescue ::Errno::EACCES => e
      raise Rex::BindFailed.new(e.message)
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_mdns_request(cli, data)
    return if data.strip.empty?

    req = Packet.encode_drb(data)

    return if req.header.qr # this is a response so ignore it because we're a server # don't process responses at all

    peer = Rex::Socket.to_authority(cli.peerhost, cli.peerport)
    asked = req.question.map(&:qname).map(&:to_s).join(', ')
    vprint_status("Received request for #{asked} from #{peer}")

    printer_name = datastore['PrinterName']
    ipp_printer_name = "#{printer_name.gsub(/ /, '_')}._ipp._tcp.local"

    req.question.each do |question|
      case question.qname.to_s
      when '_ipp._tcp.local'
        req.add_answer(Dnsruby::RR.create(
          name: '_ipp._tcp.local.',
          type: 'PTR',
          ttl: 4500,
          domainname: ipp_printer_name
        ))
        req.add_answer(Dnsruby::RR.create(
          name: ipp_printer_name,
          type: 'SRV',
          ttl: 120,
          target: "#{printer_name}.local",
          priority: 0,
          weight: 0,
          port: srvport
        ))
        req.add_answer(Dnsruby::RR.create(
          name: ipp_printer_name,
          type: 'TXT',
          ttl: 4500
        ).tap { |rr| rr.strings = [
            'txtvers=1',
            'qtotal=1',
            'ty=Printer',
            'pdl=application/postscript,application/pdf',
            'UUID=ff3332a5-a6e3-4ac7-9679-16c322f153a4',
            'printer-type=0x800683'
          ]
        })
        req.add_answer(Dnsruby::RR.create(
          name: "#{printer_name}.local",
          type: 'A',
          ttl: 120,
          address: srvhost
        ))
      end
    end

    req.question.clear
    req.update_counts
    return if req.answer.empty?

    req.header.aa = true
    response_data = Packet.generate_response(req).encode
    service.send_response(cli, response_data)
  end

  #
  # Creates Proc to handle outbound responses
  #
  def on_send_mdns_response(cli,data)
    vprint_status("Sending response to #{Rex::Socket.to_authority(cli.peerhost, cli.peerport)}")
    cli.write(data)
  end
end
