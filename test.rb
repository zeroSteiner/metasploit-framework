require 'rubygems'
require 'net/ldap'
require 'net/ntlm'
require 'net/ntlm/client'
require 'ruby_smb'

class Ntlmssp < Net::LDAP::AuthAdapter
  # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8b9dbfb2-5b6a-497a-a533-7e709cb9a982
  def bind(auth)
    ntlm_client = auth[:ntlm_client]
    raise Net::LDAP::BindingInformationInvalidError, "Invalid binding information" unless ntlm_client

    # sicilyPackageDiscovery
    message_id = @connection.next_msgid
    request = [
      Net::LDAP::Connection::LdapVersion.to_ber, "".to_ber, "".to_ber_contextspecific(9)
    ].to_ber_appsequence(Net::LDAP::PDU::BindRequest)

    @connection.send(:write, request, nil, message_id)
    pdu = @connection.queued_read(message_id)
    unless pdu.result[:matchedDN].split(';').include?('NTLM')
      raise Net::LDAP::AuthMethodUnsupportedError
    end

    type1_message = ntlm_client.init_context
    pdu = send_recv(type1_message.serialize.to_ber_contextspecific(10))
    return pdu unless pdu.result_code == 0

    sec_blob = pdu.result[:matchedDN]
    ntlmssp_offset = sec_blob.index('NTLMSSP')
    type2_blob = sec_blob.slice(ntlmssp_offset..-1)
    challenge = [type2_blob].pack('m')
    type3_message = ntlm_client.init_context(challenge)
    send_recv(type3_message.serialize.to_ber_contextspecific(11))
  end

  private

  def send_recv(body)
    message_id = @connection.next_msgid
    request = [
      Net::LDAP::Connection::LdapVersion.to_ber, "NTLM".to_ber, body
    ].to_ber_appsequence(Net::LDAP::PDU::BindRequest)

    @connection.send(:write, request, nil, message_id)
    pdu = @connection.queued_read(message_id)
    if !pdu || pdu.app_tag != Net::LDAP::PDU::BindResult
      raise Net::LDAP::NoBindResultError, "no bind result"
    end
    pdu
  end
end

Net::LDAP::AuthAdapter.register(:ntlmssp, Ntlmssp)

ldap = Net::LDAP.new :host => '192.168.159.96',
  :port => 389,
  :auth => {
    :method      => :ntlmssp,
    :ntlm_client => Net::NTLM::Client.new(
      "aliddle",
      "Password1",
      workstation: 'WORKSTATION',
      domain: 'msflab.local',
      flags: RubySMB::NTLM::DEFAULT_CLIENT_FLAGS
    )
  }

filter = Net::LDAP::Filter.eq("sAMAccountName", "aliddle")
attrs = ["mail", "cn", "sn", "objectclass"]
treebase = "dc=msflab,dc=local"

ldap.search(:ignore_server_caps => true, :base => treebase, :filter => filter) do |entry|
  puts "DN: #{entry.dn}"
  entry.each do |attribute, values|
    puts "   #{attribute}:"
    values.each do |value|
      puts "      --->#{value}"
    end
  end
end

p ldap.get_operation_result
