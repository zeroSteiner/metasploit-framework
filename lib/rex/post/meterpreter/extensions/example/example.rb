# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/example/tlv'
require 'rex/post/meterpreter/extensions/example/command_ids'

module Rex
module Post
module Meterpreter
module Extensions
module Example

###
#
# This meterpreter extension is an example that will echo a message.
#
###
class Example < Extension

  def self.extension_id
    EXTENSION_ID_EXAMPLE
  end

  def initialize(client)
    super(client, 'example')

    client.register_extension_aliases(
      [
        {
          'name' => 'example',
          'ext'  => self
        },
      ])
  end

  def echo(msg='Hello World!')
    request = Packet.create_request(COMMAND_ID_EXAMPLE_ECHO)
    request.add_tlv(TLV_TYPE_EXAMPLE_ECHO_MSG, msg)
    response = client.send_request(request)
    response.get_tlv_value(TLV_TYPE_EXAMPLE_ECHO_MSG)
  end
end

end
end
end
end
end
