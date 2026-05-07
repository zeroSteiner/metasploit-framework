# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_windows_secur32

  def self.create_library(constant_manager, library_path = 'secur32')
    dll = Library.new(library_path, constant_manager)

    dll.add_function('LsaCallAuthenticationPackage', 'NTSTATUS', [
      ['HANDLE', 'LsaHandle', 'in'],
      ['ULONG', 'AuthenticationPackage', 'in'],
      ['PBLOB', 'ProtocolSubmitBuffer', 'in'],
      ['ULONG', 'SubmitBufferLength', 'in'],
      ['PLPVOID', 'ProtocolReturnBuffer', 'out'],
      ['PULONG', 'ReturnBufferLength', 'out'],
      ['PULONG', 'ProtocolStatus', 'out']
    ])

    dll.add_function('LsaConnectUntrusted', 'NTSTATUS', [
      ['PHANDLE', 'LsaHandle', 'out']
    ])

    dll.add_function('LsaDeregisterLogonProcess', 'NTSTATUS', [
      ['HANDLE', 'LsaHandle', 'in']
    ])

    dll.add_function('LsaEnumerateLogonSessions', 'NTSTATUS', [
      ['PULONG', 'LogonSessionCount', 'out'],
      ['PLPVOID', 'LogonSessionList', 'out']
    ])

    dll.add_function('LsaFreeReturnBuffer', 'NTSTATUS', [
      ['LPVOID', 'Buffer', 'in']
    ])

    dll.add_function('LsaGetLogonSessionData', 'NTSTATUS', [
      ['PBLOB', 'LogonId', 'in'],
      ['PLPVOID', 'ppLogonSessionData', 'out']
    ])

    dll.add_function('LsaLookupAuthenticationPackage', 'NTSTATUS', [
      ['HANDLE', 'LsaHandle', 'in'],
      ['PBLOB', 'PackageName', 'in'],
      ['PULONG', 'AuthenticationPackage', 'out']
    ])

    dll.add_function('LsaLogonUser', 'NTSTATUS', [
      ['HANDLE', 'LsaHandle', 'in'],
      ['PBLOB', 'OriginName', 'in'],
      ['ULONG', 'LogonType', 'in'],
      ['ULONG', 'AuthenticationPackage', 'in'],
      ['PBLOB', 'AuthenticationInformation', 'in'],
      ['ULONG', 'AuthenticationInformationLength', 'in'],
      ['PBLOB', 'LocalGroups', 'in'],
      ['PBLOB', 'SourceContext', 'in'],
      ['PLPVOID', 'ProfileBuffer', 'out'],
      ['PULONG', 'ProfileBufferLength', 'out'],
      ['PBLOB', 'LogonId', 'out'],
      ['PHANDLE', 'Token', 'out'],
      ['PBLOB', 'Quotas', 'out'],
      ['PULONG', 'SubStatus', 'out']
    ])

    dll.add_function('LsaRegisterLogonProcess', 'NTSTATUS', [
      ['PBLOB', 'LogonProcessName', 'in'],
      ['PHANDLE', 'LsaHandle', 'out'],
      ['PULONG', 'SecurityMode', 'out']
    ])

    return dll
  end

end

end; end; end; end; end; end; end
