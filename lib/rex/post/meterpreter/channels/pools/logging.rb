# -*- coding: binary -*-

require 'rex/post/meterpreter/channels/pools/stream_pool'
require 'rex/post/meterpreter/extensions/stdapi/tlv'

module Rex
module Post
module Meterpreter
module Channels
module Streams

###
#
# Logging
# -------
#
# This class represents a channel that is associated with a logging stream
# on the remote half of the meterpreter connection.
#
###
class Logging < Rex::Post::Meterpreter::Channels::Pools::StreamPool

  ##
  #
  # Factory
  #
  ##

  def Logging.open(client)
    return Channel.create(client, 'core_logging',self, CHANNEL_FLAG_SYNCHRONOUS)
  end

  ##
  #
  # Constructor
  #
  ##

  # Initializes the file channel instance
  def initialize(client, cid, type, flags)
    super(client, cid, type, flags)
  end

end

end; end; end; end; end

