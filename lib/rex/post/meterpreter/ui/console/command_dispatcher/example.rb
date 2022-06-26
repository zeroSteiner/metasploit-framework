# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

class Console::CommandDispatcher::Example

  Klass = Console::CommandDispatcher::Example

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Example'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'echo' => 'echo a string',
    }
  end

  def cmd_echo(*args)
    unless args[0]
      print_error("Usage: echo [message]")
      return
    end
    message = args[0]
    response_message = client.example.echo(message)
    print_status("Echoed: #{response_message}")
    return true
  end
end

end
end
end
end
