# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/foobar/tlv'
require 'rex/post/meterpreter/extensions/foobar/command_ids'

module Rex
module Post
module Meterpreter
module Extensions
module Foobar

###
#
# This meterpreter extension is an example that will echo a message.
#
###
class Foobar < Extension

  def self.extension_id
    EXTENSION_ID_FOOBAR
  end

  def initialize(client)
    super(client, 'foobar')

    client.register_extension_aliases(
      [
        {
          'name' => 'foobar',
          'ext'  => self
        },
      ])
  end

  def echo(msg='Hello World!')
    request = Packet.create_request(COMMAND_ID_FOOBAR_ECHO)
    request.add_tlv(TLV_TYPE_FOOBAR_ECHO_MSG, msg)
    response = client.send_request(request)
    response.get_tlv_value(TLV_TYPE_FOOBAR_ECHO_MSG)
  end
end

end
end
end
end
end
