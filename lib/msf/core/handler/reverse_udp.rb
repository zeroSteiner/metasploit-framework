# -*- coding: binary -*-
require 'rex/socket'
require 'thread'

# -*- coding: binary -*-
require 'rex/sync/thread_safe'
require 'bindata'

module DataGramStream

  class DataGramHeader < BinData::Record
    # format specification:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Version|R|P|A|S|                    Sequence                   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    endian :big

    SIZE = 4
    VERSION = 1

    default_parameter version: 1

    bit4   :version, :initial_value => :version
    bit1   :reserved
    bit1   :psh_flag
    bit1   :ack_flag
    bit1   :syn_flag
    uint24 :sequence

    rest   :data
  end

  def init_dgstream_server(hello, opts = {})
    @sequence = nil
    dgh = read_datagram(opts)
    return false if dgh.nil?
    return false unless dgh.psh_flag == 0
    return false unless dgh.ack_flag == 0
    return false unless dgh.syn_flag == 1
    return false unless dgh.sequence != 0
    @sequence = dgh.sequence
    @mutex = Mutex.new
    @condition = ConditionVariable.new
    @acked = false
    return send_ack(opts)
  end

  def write(buf, opts = {})
    total_sent = 0
    max_block_size = 65507

    frames = []
    while buf.length > max_block_size
      frames << buf[0..max_block_size - 1]
      buf = buf[max_block_size..-1]
    end
    frames << buf if buf.length > 0

    frames.each do |frame|
      success = false
      5.times do |iteration|
        success = write_frame(frame, opts)
        break if success
        # use an exponential backup to avoid congestion
        # todo: ensure these values are resonable
        sleep((100.0 ** (iteration + 1.0)) / 1000.0)
      end
      raise IOError unless success
    end

    buf.length
  end

  alias_method :put, :write

  def read(length = nil, opts = {})
    buffer = ''
    while buffer.length < length
      frame = read_frame
      buffer << frame unless frame.nil?
    end

    buffer
  end

  protected

  def read_frame(opts = {})
    dgh = read_datagram(opts)
    return nil if dgh.nil?
    send_ack(opts)
    return dgh.data
  end

  def write_frame(frame, opts = {})
    @mutex.synchronize do
      @acked = false
      dgh = DataGramHeader.new(psh_flag: 1, sequence: @sequence, data: frame)
      write_datagram(dgh, opts)
      @condition.wait(@mutex, 5)  # this timeout (5) should be configurable or come from some place intelligent
      return false unless @acked
      return true
    end
  end

  def read_datagram(opts = {})
    5.times do |iteration|
      s = Rex::ThreadSafe.select([fd], nil, nil, 0.2)
      next if (s.nil? || s[0].nil?)

      # todo: this should be a configurable block size
      received = fd.read_nonblock(65507)

      next unless received.length >= DataGramHeader::SIZE
      dgh = DataGramHeader.read(received)
      next unless dgh.version == DataGramHeader::VERSION
      if dgh.ack_flag == 1 and dgh.sequence == @sequence
        @acked = true
        @sequence += 1
        @condition.signal
        next
      end
      return dgh if @sequence.nil? || dgh.sequence == @sequence
    end
    return nil
  end

  def write_datagram(dg, opts = {})
    # todo: this needs to address the fact that the packet waiter is getting the
    # ack frame, a mutex might do the trick here
    begin
      5.times do |iteration|
        s = Rex::ThreadSafe.select(nil, [fd], nil, 0.2)
        break unless (s.nil? || s[0].nil?)
      end
      raw = dg.to_binary_s
      sent = fd.write_nonblock(raw)
      # here we verify that the entire datagram was sent and acknowledged
      # we don't account for partial writes due to the nature of the protocol
      return false unless sent == raw.length
    rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
      Rex::ThreadSafe.select(nil, [fd], nil, 0.5)
      retry
    rescue ::IOError, ::Errno::EPIPE
      return nil
    end

    return true
  end

  def recv_ack(sequence, opts = {})
    dgh = read_datagram(opts)
    return false if dgh.nil?
    return dgh.ack_flag == 1
  end

  def send_ack(opts = {})
    write_datagram(DataGramHeader.new(ack_flag: 1, sequence: @sequence), opts)
    @sequence += 1
  end

end

module Msf
module Handler

###
#
# This module implements the reverse UDP handler.  This means
# that it listens on a port waiting for a connection until
# either one is established or it is told to abort.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module ReverseUdp

  include Msf::Handler

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_udp'.
  #
  def self.handler_type
    return "reverse_udp"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  # A string suitable for displaying to the user
  #
  # @return [String]
  def human_name
    "reverse UDP"
  end

  #
  # Initializes the reverse UDP handler and ads the options that are required
  # for all reverse UDP payloads, like local host and local port.
  #
  def initialize(info = {})
    super

    register_options(
      [
        Opt::LHOST,
        Opt::LPORT(4444)
      ], Msf::Handler::ReverseUdp)

    # XXX: Not supported by all modules
    register_advanced_options(
      [
        OptAddress.new('ReverseListenerBindAddress', [ false, 'The specific IP address to bind to on the local system']),
        OptInt.new('ReverseListenerBindPort', [ false, 'The port to bind to on the local system if different from LPORT' ]),
        OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener']),
        OptBool.new('ReverseListenerThreaded', [ true, 'Handle every connection in a new thread (experimental)', false])
      ] +
      Msf::Opt::stager_retry_options,
      Msf::Handler::ReverseUdp)

    self.conn_threads = []
  end

  #
  # Starts the listener but does not actually attempt
  # to accept a connection.  Throws socket exceptions
  # if it fails to start the listener.
  #
  def setup_handler
    ex = false

    comm = case datastore['ReverseListenerComm'].to_s
      when "local"; ::Rex::Socket::Comm::Local
      when /\A[0-9]+\Z/; framework.sessions[datastore['ReverseListenerComm'].to_i]
      else; nil
      end
    unless comm.is_a? ::Rex::Socket::Comm
      comm = nil
    end

    local_port = bind_port
    addrs = bind_address

    addrs.each { |ip|
      begin

        self.listener_sock = Rex::Socket::Udp.create(
          'LocalHost' => ip,
          'LocalPort' => local_port,
          'Comm'      => comm,
          'Context'   =>
            {
              'Msf'        => framework,
              'MsfPayload' => self,
              'MsfExploit' => assoc_exploit
            })

        ex = false

        comm_used = comm || Rex::Socket::SwitchBoard.best_comm( ip )
        comm_used = Rex::Socket::Comm::Local if comm_used == nil

        if( comm_used.respond_to?( :type ) and comm_used.respond_to?( :sid ) )
          via = "via the #{comm_used.type} on session #{comm_used.sid}"
        else
          via = ""
        end

        print_status("Started #{human_name} handler on #{ip}:#{local_port} #{via}")
        break
      rescue
        ex = $!
        print_error("Handler failed to bind to #{ip}:#{local_port}")
      end
    }
    raise ex if (ex)
  end

  #
  # Closes the listener socket if one was created.
  #
  def cleanup_handler
    stop_handler

    # Kill any remaining handle_connection threads that might
    # be hanging around
    conn_threads.each { |thr|
      thr.kill rescue nil
    }
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    queue = ::Queue.new

    local_port = bind_port

    self.listener_thread = framework.threads.spawn("ReverseUdpHandlerListener-#{local_port}", false, queue) { |lqueue|
      loop do
        # Accept a client connection
        begin
          inbound, peerhost, peerport = self.listener_sock.recvfrom
          next if peerhost.nil?
          cli_opts = {
            'PeerPort'  => peerport,
            'PeerHost'  => peerhost,
            'LocalPort' => self.listener_sock.localport,
            'Comm'      => self.listener_sock.respond_to?(:comm) ? self.listener_sock.comm : nil
          }

          # unless ['::', '0.0.0.0'].any? {|alladdr| self.listener_sock.localhost == alladdr }
          #   cli_opts['LocalHost'] = self.listener_sock.localhost
          # end

          client = Rex::Socket.create_udp(cli_opts)
          client.extend(Rex::IO::Stream)
          if ! client
            wlog("ReverseUdpHandlerListener-#{local_port}: No client received in call to accept, exiting...")
            break
          end

          self.pending_connections += 1
          lqueue.push([client, inbound])
        rescue ::Exception
          wlog("ReverseUdpHandlerListener-#{local_port}: Exception raised during listener accept: #{$!}\n\n#{$@.join("\n")}")
          break
        end
      end
    }

    self.handler_thread = framework.threads.spawn("ReverseUdpHandlerWorker-#{local_port}", false, queue) { |cqueue|
      loop do
        begin
          client, inbound = cqueue.pop

          if ! client
            elog("ReverseUdpHandlerWorker-#{local_port}: Queue returned an empty result, exiting...")
            break
          end

          # Timeout and datastore options need to be passed through to the client
          opts = {
            :datastore    => datastore,
            :expiration   => datastore['SessionExpirationTimeout'].to_i,
            :comm_timeout => datastore['SessionCommunicationTimeout'].to_i,
            :retry_total  => datastore['SessionRetryTotal'].to_i,
            :retry_wait   => datastore['SessionRetryWait'].to_i,
            :udp_session  => inbound
          }

          if datastore['ReverseListenerThreaded']
            self.conn_threads << framework.threads.spawn("ReverseUdpHandlerSession-#{local_port}-#{client.peerhost}", false, client) { |client_copy|
              handle_connection(client_copy, opts)
            }
          else
            handle_connection(client, opts)
          end
        rescue ::Exception
          elog("Exception raised from handle_connection: #{$!.class}: #{$!}\n\n#{$@.join("\n")}")
        end
      end
    }

  end

  def create_session(client, opts={})
    client.extend(DataGramStream)
    client.init_dgstream_server(opts)
    super
  end

  #
  # Stops monitoring for an inbound connection.
  #
  def stop_handler
    # Terminate the listener thread
    if (self.listener_thread and self.listener_thread.alive? == true)
      self.listener_thread.kill
      self.listener_thread = nil
    end

    # Terminate the handler thread
    if (self.handler_thread and self.handler_thread.alive? == true)
      self.handler_thread.kill
      self.handler_thread = nil
    end

    if (self.listener_sock)
      self.listener_sock.close
      self.listener_sock = nil
    end
  end

protected

  def bind_port
    port = datastore['ReverseListenerBindPort'].to_i
    port > 0 ? port : datastore['LPORT'].to_i
  end

  def bind_address
    # Switch to IPv6 ANY address if the LHOST is also IPv6
    addr = Rex::Socket.resolv_nbo(datastore['LHOST'])
    # First attempt to bind LHOST. If that fails, the user probably has
    # something else listening on that interface. Try again with ANY_ADDR.
    any = (addr.length == 4) ? "0.0.0.0" : "::0"

    addrs = [ Rex::Socket.addr_ntoa(addr), any  ]

    if not datastore['ReverseListenerBindAddress'].to_s.empty?
      # Only try to bind to this specific interface
      addrs = [ datastore['ReverseListenerBindAddress'] ]

      # Pick the right "any" address if either wildcard is used
      addrs[0] = any if (addrs[0] == "0.0.0.0" or addrs == "::0")
    end

    addrs
  end

  attr_accessor :listener_sock # :nodoc:
  attr_accessor :listener_thread # :nodoc:
  attr_accessor :handler_thread # :nodoc:
  attr_accessor :conn_threads # :nodoc:
end

end
end
