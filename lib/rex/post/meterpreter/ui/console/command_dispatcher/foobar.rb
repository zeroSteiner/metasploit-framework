# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

class Console::CommandDispatcher::Foobar

  Klass = Console::CommandDispatcher::Foobar

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Foobar'
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
    response_message = client.foobar.echo(message)
    print_status("Echoed: #{response_message}")
    return true
  end
end

end
end
end
end
