# -*- coding: binary -*-

module Rex
module Proto
module SMB
class SimpleClient

class OpenPipe < OpenFile

  # Valid modes are: 'trans' and 'rw'
  attr_accessor :mode

  def initialize(*args)
    super(*args)
    self.mode = 'rw'
    @buff = ''
  end

  def read_buffer(length, offset=0)
    length ||= @buff.length
    @buff.slice!(0, length)
  end

  def read_ruby_smb(length, offset, depth = 0)
    if length.nil?
      max_size = client.open_files[client.last_file_id].size
      fptr = offset

      chunk = [max_size, chunk_size].min

      data = client.read(file_id, fptr, chunk).pack('C*')
      fptr = data.length

      while data.length < max_size
        if (max_size - data.length) < chunk
          chunk = max_size - data.length
        end
        data << client.read(file_id, fptr, chunk).pack('C*')
        fptr = data.length
      end
    else
      begin
        client.read(file_id, offset, length).pack('C*')
      rescue RubySMB::Error::UnexpectedStatusCode => e
        if e.message == 'STATUS_PIPE_EMPTY' && depth < 20
          read_ruby_smb(length, offset, depth + 1)
        else
          raise e
        end
      end
    end
  end

  def read(length = nil, offset = 0)
    case self.mode
    when 'trans'
      read_buffer(length, offset)
    when 'rw'
      super(length, offset)
    else
      raise ArgumentError
    end
  end

  def write(data, offset = 0)
    case self.mode
    when 'trans'
      write_trans(data, offset)
    when 'rw'
      super(data, offset)
    else
      raise ArgumentError
    end
  end

  def write_trans(data, offset=0)
    @buff << self.client.last_file.nmpipe_send_recv(data)
  end

  def peek_ruby_smb
    self.client.last_file.peek_available
  end

  def peek
    peek_ruby_smb
  end
end
end
end
end
end
