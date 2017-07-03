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

require 'rex/post/meterpreter/extensions/stdapi/railgun/library_function'
require 'rex/post/meterpreter/extensions/stdapi/railgun/library_helper'
require 'rex/post/meterpreter/extensions/stdapi/railgun/buffer_item'
require 'rex/post/meterpreter/extensions/stdapi/railgun/tlv'
require 'rex/post/meterpreter/packet'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

#
# Represents a library, e.g. kernel32.dll
#
class Library

  include LibraryHelper

  attr_accessor :functions
  attr_reader   :library_path

  def initialize(library_path, consts_mgr)
    @library_path = library_path

    # needed by LibraryHelper
    @consts_mgr = consts_mgr

    self.functions = {}
  end

  def known_function_names
    return functions.keys
  end

  def get_function(name)
    return functions[name]
  end

  #
  # Perform a function call in this library on the remote system.
  #
  # Returns a Hash containing the return value, the result of GetLastError(),
  # and any +inout+ parameters.
  #
  # Raises an exception if +function+ is not a known function in this library,
  # i.e., it hasn't been defined in a Def.
  #
  def call_function(function, args, client)
    unless function.instance_of? LibraryFunction
      func_name = function.to_s

      unless known_function_names.include? func_name
        raise "Library-function #{func_name} not found. Known functions: #{PP.pp(known_function_names, '')}"
      end

      function = get_function(func_name)
    end

    return process_function_call(function, args, client)
  end

  #
  # Define a function for this library.
  #
  # Every function argument is described by a tuple (type,name,direction)
  #
  # Example:
  #   add_function("MessageBoxW",   # name
  #     "DWORD",                    # return value
  #     [                           # params
  #	   ["DWORD","hWnd","in"],
  #      ["PWCHAR","lpText","in"],
  #      ["PWCHAR","lpCaption","in"],
  #      ["DWORD","uType","in"],
  #     ])
  #
  # Use +remote_name+ when the actual library name is different from the
  # ruby variable.  You might need to do this for example when the actual
  # func name is myFunc@4 or when you want to create an alternative version
  # of an existing function.
  #
  # When the new function is called it will return a list containing the
  # return value and all inout params.  See #call_function.
  #
  def add_function(name, return_type, params, remote_name=nil, calling_conv='stdcall')
    if remote_name == nil
      remote_name = name
    end
    @functions[name] = LibraryFunction.new(return_type, params, remote_name, calling_conv)
  end

  private

  def process_function_call(function, args, client)
    raise "#{function.params.length} arguments expected. #{args.length} arguments provided." unless args.length == function.params.length

    if client.native_arch == ARCH_X64
      native = 'Q<'
    else
      native = 'V'
    end

    call_data = assemble_call_data(function, args, native)

    #puts "\n\nsending Stuff to meterpreter"
    request = Packet.create_request('stdapi_railgun_api')
    request.add_tlv(TLV_TYPE_RAILGUN_SIZE_OUT, call_data[:out_only_size])
    request.add_tlv(TLV_TYPE_RAILGUN_STACKBLOB, call_data[:stack_blob])
    request.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_IN, call_data[:in_only_buffer])
    request.add_tlv(TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT, call_data[:inout_buffer])
    request.add_tlv(TLV_TYPE_RAILGUN_LIBNAME, @library_path)
    request.add_tlv(TLV_TYPE_RAILGUN_FUNCNAME, function.remote_name)
    request.add_tlv(TLV_TYPE_RAILGUN_CALLCONV, function.calling_conv)

    response = client.send_request(request)

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
    
    return_hash['return'] = get_return_value(function.return_type, rec_return_value, native)
    return_hash.merge!(disassemble_buffer(call_data[:inout_layout], rec_inout_buffers, args, native))
    return_hash.merge!(disassemble_buffer(call_data[:out_only_layout], rec_out_only_buffers, args, native))

    #puts "finished"
#		puts("
#=== START of proccess_function_call snapshot ===
#		{
#			:platform => '#{native == 'Q' ? 'x64/windows' : 'x86/windows'}',
#			:name => '#{function.remote_name}',
#			:params => #{function.params},
#			:return_type => '#{function.return_type}',
#			:library_name => '#{@library_path}',
#			:ruby_args => #{args.inspect},
#			:request_to_client => {
#				TLV_TYPE_RAILGUN_SIZE_OUT => #{out_only_size_bytes},
#				TLV_TYPE_RAILGUN_STACKBLOB => #{literal_pairs_blob.inspect},
#				TLV_TYPE_RAILGUN_BUFFERBLOB_IN => #{in_only_buffer.inspect},
#				TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT => #{inout_buffer.inspect},
#				TLV_TYPE_RAILGUN_LIBNAME => '#{@library_path}',
#				TLV_TYPE_RAILGUN_FUNCNAME => '#{function.remote_name}',
#			},
#			:response_from_client => {
#				TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT => #{rec_inout_buffers.inspect},
#				TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT => #{rec_out_only_buffers.inspect},
#				TLV_TYPE_RAILGUN_BACK_RET => #{rec_return_value.inspect},
#				TLV_TYPE_RAILGUN_BACK_ERR => #{rec_last_error},
#			},
#			:returned_hash => #{return_hash.inspect},
#		},
#=== END of proccess_function_call snapshot ===
#		")
#
    return return_hash
  end

end

end; end; end; end; end; end;
