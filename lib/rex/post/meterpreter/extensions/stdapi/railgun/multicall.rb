# -*- coding: binary -*-
# Copyright (c) 2010, patrickHVE@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The names of the author may not be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL patrickHVE@googlemail.com BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'pp'
require 'enumerator'
require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/extensions/stdapi/railgun/library_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/buffer_item'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

# A easier way to call multiple functions in a single request
class MultiCaller

    include LibraryHelper

    def initialize(client, parent, consts_mgr)
      @parent = parent
      @client = client

      # needed by LibraryHelper
      @consts_mgr = consts_mgr

      if @client.native_arch == ARCH_X64
        @native = 'Q<'
      else
        @native = 'V'
      end
    end

    def call(functions)
      request = Packet.create_request('stdapi_railgun_api_multi')
      function_results = []
      layouts          = []
      functions.each do |f|
        lib_name, function, args = f
        lib_host = @parent.get_library(lib_name)

        raise "Library #{lib_name} has not been loaded" unless lib_host

        unless function.instance_of? LibraryFunction
          function = lib_host.functions[function]
          raise "Library #{lib_name} function #{function} has not been defined" unless function
        end

        raise "#{function.params.length} arguments expected. #{args.length} arguments provided." unless args.length == function.params.length

        call_data = assemble_call_data(function, args, @native)

        group = Rex::Post::Meterpreter::GroupTlv.new(TLV_TYPE_RAILGUN_MULTI_GROUP)
        group.add_tlv(TLV_TYPE_RAILGUN_SIZE_OUT, call_data[:out_only_size])
        group.add_tlv(TLV_TYPE_RAILGUN_STACKBLOB, call_data[:stack_blob])
        group.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_IN, call_data[:in_only_buffer])
        group.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, call_data[:inout_buffer])
        group.add_tlv(TLV_TYPE_RAILGUN_LIBNAME, lib_host.library_path)
        group.add_tlv(TLV_TYPE_RAILGUN_FUNCNAME, function.remote_name)
        request.tlvs << group

        layouts << [call_data[:inout_layout], call_data[:out_only_layout]]
      end

      call_results = []
      res = @client.send_request(request)
      res.each(TLV_TYPE_RAILGUN_MULTI_GROUP) do |val|
        call_results << val
      end

      functions.each do |f|
        lib_name, function, args = f
        lib_host = @parent.get_library(lib_name)
        function = lib_host.functions[function] unless function.instance_of? LibraryFunction
        response = call_results.shift
        inout_layout, out_only_layout = layouts.shift

        rec_inout_buffers = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT)
        rec_out_only_buffers = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT)
        rec_return_value = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_RET)
        rec_last_error = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_ERR)
        rec_err_msg = response.get_tlv_value(TLV_TYPE_RAILGUN_BACK_MSG)

        # Error messages come back with trailing CRLF, so strip it out
        # if we do get a message.
        rec_err_msg.strip! unless rec_err_msg.nil?

        # The hash the function returns
        return_hash = {
          'GetLastError' => rec_last_error,
          'ErrorMessage' => rec_err_msg
        }

        return_hash['return'] = get_return_value(function.return_type, rec_return_value, @native)
        return_hash.merge!(disassemble_buffer(inout_layout, rec_inout_buffers, args, @native))
        return_hash.merge!(disassemble_buffer(out_only_layout, rec_out_only_buffers, args, @native))

        function_results << return_hash
      end
      function_results
    end
    # process_multi_function_call

  protected

end # MultiCall

end; end; end; end; end; end
