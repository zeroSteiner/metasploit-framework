# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_wldap32

  def self.create_library(constant_manager, library_path = 'wldap32')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('ldap_sslinitA', 'LPVOID',[
        ['PCHAR', 'HostName', 'in'],
        ['DWORD', 'PortNumber', 'in'],
        ['DWORD', 'secure', 'in']
    ], 'ldap_sslinitA', "cdecl")

    dll.add_function('ldap_bind_sA', 'DWORD',[
        ['LPVOID', 'ld', 'in'],
        ['PCHAR', 'dn', 'in'],
        ['PCHAR', 'cred', 'in'],
        ['DWORD', 'method', 'in']
    ], 'ldap_bind_sA', "cdecl")

    dll.add_function('ldap_search_sA', 'DWORD',[
        ['LPVOID', 'ld', 'in'],
        ['PCHAR', 'base', 'in'],
        ['ULONG', 'scope', 'in'],
        ['PCHAR', 'filter', 'in'],
        ['PCHAR', 'attrs[]', 'in'],
        ['ULONG', 'attrsonly', 'in'],
        ['PLPVOID', 'res', 'out']
    ], 'ldap_search_sA', "cdecl")

    dll.add_function('ldap_set_option', 'DWORD',[
        ['ULONG_PTR', 'ld', 'in'],
        ['DWORD', 'option', 'in'],
        ['DWORD', 'invalue', 'in']
    ], 'ldap_set_option', "cdecl")

    dll.add_function('ldap_search_ext_sA', 'DWORD',[
        ['LPVOID', 'ld', 'in'],
        ['PCHAR', 'base', 'in'],
        ['ULONG', 'scope', 'in'],
        ['PCHAR', 'filter', 'in'],
        ['PCHAR', 'attrs[]', 'in'],
        ['ULONG', 'attrsonly', 'in'],
        ['LPVOID', 'pServerControls', 'in'],
        ['LPVOID', 'pClientControls', 'in'],
        ['PBLOB', 'pTimeout', 'in'],
        ['ULONG', 'SizeLimit', 'in'],
        ['PLPVOID', 'res', 'out']
    ], 'ldap_search_ext_sA', "cdecl")

    dll.add_function('ldap_count_entries', 'DWORD',[
        ['LPVOID', 'ld', 'in'],
        ['LPVOID', 'res', 'in']
    ], "ldap_count_entries", "cdecl")

    dll.add_function('ldap_first_entry', 'ULONG_PTR',[
        ['LPVOID', 'ld', 'in'],
        ['LPVOID', 'res', 'in']
    ], 'ldap_first_entry', "cdecl")

    dll.add_function('ldap_next_entry', 'ULONG_PTR',[
        ['LPVOID', 'ld', 'in'],
        ['LPVOID', 'entry', 'in']
    ], 'ldap_next_entry', "cdecl")

    dll.add_function('ldap_first_attributeA', 'PCHAR',[
        ['LPVOID', 'ld', 'in'],
        ['LPVOID', 'entry', 'in'],
        ['PLPVOID', 'ptr', 'out']
    ], 'ldap_first_attributeA', "cdecl")

    dll.add_function('ldap_next_attributeA', 'PCHAR',[
        ['DWORD', 'ld', 'in'],
        ['DWORD', 'entry', 'in'],
        ['ULONG_PTR', 'ptr', 'inout']
    ], 'ldap_next_attributeA', "cdecl")

    dll.add_function('ldap_count_values', 'DWORD',[
        ['PLPVOID', 'vals', 'in'],
    ], 'ldap_count_values', "cdecl")

    dll.add_function('ldap_get_values', 'PLPVOID',[
        ['LPVOID', 'ld', 'in'],
        ['LPVOID', 'entry', 'in'],
        ['PCHAR', 'attr', 'in']
    ], 'ldap_get_values', "cdecl")

    dll.add_function('ldap_value_free', 'DWORD',[
        ['PLPVOID', 'vals', 'in'],
    ], 'ldap_value_free', "cdecl")

    dll.add_function('ldap_memfree', 'VOID',[
        ['PCHAR', 'block', 'in'],
    ], 'ldap_memfree', "cdecl")

    dll.add_function('ber_free', 'VOID',[
        ['LPVOID', 'pBerElement', 'in'],
        ['DWORD', 'fbuf', 'in'],
    ], 'ber_free', "cdecl")

    dll.add_function('LdapGetLastError', 'DWORD', [], 'LdapGetLastError', "cdecl")

    dll.add_function('ldap_err2string', 'PCHAR',[
        ['DWORD', 'err', 'in']
    ], 'ldap_err2string', "cdecl")

    dll.add_function('ldap_msgfree', 'DWORD', [
      ['LPVOID', 'res', 'in']
    ], 'ldap_msgfree', "cdecl")

    dll.add_function('ldap_unbind', 'DWORD', [
      ['LPVOID', 'ld', 'in']
    ], 'ldap_unbind', "cdecl")
    return dll
  end

end

end; end; end; end; end; end; end


