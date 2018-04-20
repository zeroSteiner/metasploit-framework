# -*- coding: binary -*-

module Msf
class Post
module Windows

module ProcessInjection

  include Msf::Post::Windows::Process

  def initialize(info = {})
    super
    register_options(
    [
      OptString.new('PROCESS_NAME', [false, 'Name of the process in which to inject the payload.']),
      OptInt.new('PID', [false, 'PID of the process in which to inject the payload.']),
    ], self.class)
  end

  def get_pid
    if (!datastore['PID'] && !datastore['PROCESS_NAME']) || (datastore['PID'] && datastore['PROCESS_NAME'])
      fail_with(::Msf::Module::Failure::BadConfig, "One of PID or PROCESS_NAME must be specified.")
    end

    return has_pid?(datastore['PID']) ? datastore['PID'] : nil if datastore['PID']

    proc = find_process({'name' => datastore['PROCESS_NAME']})
    return proc ? proc['pid'] : nil
  end

  def has_pid?(pid)
    proc = find_process({'pid' => pid})
    return proc ? proc['pid'] : nil
  end

  private

  def find_process(filter)
    begin
      procs = client.sys.process.processes
    rescue Rex::Post::Meterpreter::RequestError
      print_error("Unable to enumerate processes")
      return nil
    end

    procs.each do |proc|
      match = true
      filter.each do |key, value|
        if proc[key] == value
          match = false
          break
        end
      end
      return proc if match
    end
  end

end # ProcessInjection
end # Windows
end # Post
end # Msf
