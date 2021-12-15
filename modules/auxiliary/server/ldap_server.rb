##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP::Server

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Native LDAP Server (Example)',
      'Description'    => %q{
        This module provides a Rex based LDAP service to expose the
        native Rex LDAP server functionality created during log4shell
        development.
      },
      'Author'         => 'RageLtMan <rageltman[at]sempervictus>',
      'License'        => MSF_LICENSE,
      'References'     => []
    ))
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    begin
      start_service
      service.wait
    rescue Rex::BindFailed => e
      print_error "Failed to bind to port #{datastore['SRVPORT']}: #{e.message}"
    ensure
      stop_service
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(client, data)
    return if data.strip.empty?
    data.extend(Net::BER::Extensions::String)
    begin
      pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
      vprint_status("LDAP request data remaining: #{data}") if data.length > 0
      resp = case pdu.app_tag
      when Net::LDAP::PDU::BindRequest # bind request
        # vprint_good("Received LDAP bind request from #{client} - #{pp pdu}")
        client.authenticated = true
        service.encode_ldap_response(
          pdu.message_id,
          Net::LDAP::ResultCodeSuccess,
          '',
          '',
          Net::LDAP::PDU::BindResult
        )
      when Net::LDAP::PDU::SearchRequest # search request
        # vprint_good("Received LDAP search request from #{client} - #{pp pdu}")
        if client.authenticated or datastore['LDAP_AUTH_BYPASS']
          # Perform query against some loaded LDIF structure
          filter = Net::LDAP::Filter.parse_ldap_filter(pdu.search_parameters[:filter])
          attrs  = pdu.search_parameters[:attributes].empty? ? :all : pdu.search_parameters[:attributes]
          res = service.search_ldif(filter, pdu.message_id, attrs)
          if res.nil? or res.empty?
            # vprint_status("No LDAP search results for #{filter}/#{attrs} in #{self.service.ldif}")
            service.encode_ldap_response(pdu.message_id, Net::LDAP::ResultCodeNoSuchObject, "", "No such object", 5)
          else
            # vprint_status("LDAP search results for #{client} - #{pp pdu}: #{pp res}")
            # Send the results and return success message for callback completion
            cli.write(res)
            service.encode_ldap_response(pdu.message_id, Net::LDAP::ResultCodeSuccess, "", "Search success", 5)
          end
        else
          service.encode_ldap_response(pdu[0].to_i, 50, "", "Not authenticated", 5)
        end
      else
        # vprint_status("Received unknown LDAP request from #{client} - #{pp pdu}")
        service.encode_ldap_response(pdu.message_id, Net::LDAP::ResultCodeUnwillingToPerform, "", "I'm sorry Dave, I can't do that", 5)
      end
      resp.nil? ? client.close : on_send_response(client, resp)
    rescue => e
      print_error("Failed to handle LDAP request due to #{e}")
      client.close
    end
  end


end
