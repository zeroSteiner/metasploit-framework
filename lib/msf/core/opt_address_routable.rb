# -*- coding: binary -*-

module Msf

  ###
  #
  # Routable network address option.
  #
  ###
  class OptAddressRoutable < OptAddress

    def valid?(value, check_empty: true, datastore: nil)
      return false if Rex::Socket.is_ip_addr?(value) && Rex::Socket.addr_atoi(value) == 0

      if Rex::Socket.is_ipv4?(value)
        ip_addr = IPAddr.new(value)
        return false if IPAddr.new('0.0.0.0/0').include? ip_addr   # this network
        return false if IPAddr.new('224.0.0.0/4').include? ip_addr # multicast
        return false if IPAddr.new('240.0.0.0/4').include? ip_addr # reserved
        return false if IPAddr.new('255.255.255.255') == ip_addr   # broadcast
      end

      super
    end
  end
end
