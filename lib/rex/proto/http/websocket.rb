# -*- coding: binary -*-
require 'bindata'

module Rex
module Proto
module Http
module WebSocket

module Interface
  def put_frame(frame, opts={})
    put(frame.to_binary_s, opts=opts)
  end

  def put_wsbinary(value, opts={})
    put(Frame.from_binary(value), opts=opts)

  def put_wstext(value, opts={})
    put(Frame.from_text(value), opts=opts)
  end

  def get_frame(opts={})
    Frame.read(self)
  end
end

class Opcode < BinData::Bit4
  VALUES = {
    0x0 => :Continuation,
    0x1 => :Text,
    0x2 => :Binary,
    0x8 => :ConnectionClose,
    0x9 => :Ping,
    0xa => :Pong
  }
  VALUES.each_pair { |val,str| const_set(str.upcase, val) }
  default_parameter assert: -> { VALUES.keys.include?(value) }

  def as_enum
    VALUES[value]
  end
end

class Frame  < BinData::Record
  endian :big
  hide   :rsv1, :rsv2, :rsv3

  bit1   :fin
  bit1   :rsv1
  bit1   :rsv2
  bit1   :rsv3
  opcode :opcode
  bit1   :mask
  bit7   :payload_len_sm
  uint16 :payload_len_md, onlyif: -> { payload_len_sm == 126 }
  uint64 :payload_len_lg, onlyif: -> { payload_len_sm == 127 }
  uint32 :masking_key, onlyif: -> { mask == 1 }
  string :payload_data, read_length: -> { payload_len }

  def self.from_binary(value)
    frame = Frame.new(opcode: Opcode::BINARY)
    frame.payload_len = value.length
    frame.payload_data = value
    frame
  end

  def self.from_text(value)
    frame = Frame.new(opcode: Opcode::TEXT)
    frame.payload_len = value.length
    frame.payload_data = value
    frame
  end

  def payload_len
    case payload_len_sm
    when 127
      payload_len_lg
    when 126
      payload_len_md
    else
      payload_len_sm
    end
  end

  def payload_len=(value)
    if value < 126
      @payload_len_sm = value
    elsif value < 0xffff
      @payload_len_sm = 126
      @payload_len_md = value
    elsif value < 0x7fffffffffffffff
      @payload_len_sm = 127
      @payload_len_lg = value
    else
      raise ArgumentError, 'payload length is outside the acceptable range'
    end
  end
end

end
end
end
end
end
