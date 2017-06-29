# -*- coding: binary -*-

require 'bindata'

module Msf
class Post
module Windows

module Minidump

  #
  # Miscellaneous Structures
  #

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724833(v=vs.85).aspx
  class OsVersionInfoExA < BinData::Record
    endian :little

    uint32 :os_version_info_size
    uint32 :major_version
    uint32 :minor_version
    uint32 :build_number
    uint32 :platform_id
    string :csd_version, :length => 128, :trim_padding => true
    uint16 :service_pack_major
    uint16 :service_pack_minor
    uint16 :suite_mask
    uint8  :product_type
    uint8  :reserved
  end

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724958(v=vs.85).aspx
  class SystemInfo_x64 < BinData::Record
    endian :little

    uint16 :processor_architecture
    uint16 :reserved
    uint32 :page_size
    uint64 :minimum_application_address
    uint64 :maximum_application_address
    uint64 :active_processor_mask
    uint32 :number_of_processors
    uint32 :processor_type
    uint32 :allocation_granularity
    uint16 :processor_level
    uint16 :processor_revision
  end

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724958(v=vs.85).aspx
  class SystemInfo_x86 < BinData::Record
    endian :little

    uint16 :processor_architecture
    uint16 :reserved
    uint32 :page_size
    uint32 :minimum_application_address
    uint32 :maximum_application_address
    uint32 :active_processor_mask
    uint32 :number_of_processors
    uint32 :processor_type
    uint32 :allocation_granularity
    uint16 :processor_level
    uint16 :processor_revision
  end

  #
  # MINIDUMP_* Structures
  #

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680365(v=vs.85).aspx
  class MinidumpDirectory < BinData::Record
    endian :little

    uint32 :stream_type

    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680383(v=vs.85).aspx
    struct :location do
      endian :little
      uint32 :data_size
      uint32 :rva
    end
  end

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680378(v=vs.85).aspx
  class MinidumpHeader < BinData::Record
    endian :little

    uint32 :signature
    uint32 :version
    uint32 :number_of_streams
    uint32 :rva
    uint32 :check_sum
    uint32 :time_date_stamp
    uint64 :flags
  end

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680386(v=vs.85).aspx
  class MinidumpMemoryInfo < BinData::Record
    endian :little

    uint64 :base_address
    uint64 :allocation_base
    uint32 :allocation_protect
    uint32 :alignment_1
    uint64 :region_size
    uint32 :state
    uint32 :protect
    uint32 :page_type # actually type but that's reserved by BinData::Record
    uint32 :alignment_2
  end

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680385(v=vs.85).aspx
  class MinidumpMemoryInfoList < BinData::Record
    endian :little

    uint32 :size_of_header
    uint32 :size_of_entry
    uint64 :number_of_entries
  end

  # https://msdn.microsoft.com/en-us/library/windows/desktop/ms680396(v=vs.85).aspx
  class MinidumpSystemInfo < BinData::Record
    endian :little

    uint16 :processor_architecture
    uint16 :processor_level
    uint16 :processor_revision
    uint8  :number_of_processors
    uint8  :product_type
    uint32 :major_version
    uint32 :minor_version
    uint32 :build_number
    uint32 :platform_id
    uint16 :suite_mask
    uint16 :reserved_1_2
    array  :vendor_id, :type => :uint32, :initial_length => 3
    uint32 :version_information
    uint32 :feature_information
    uint32 :amd_extended_cpu_features
  end

  def get_stream_minidump_system_info
    if session.native_arch == 'x64'
      system_info = SystemInfo_x64.new
    else
      system_info = SystemInfo_x86.new
    end

    result = session.railgun.kernel32.GetNativeSystemInfo(system_info.num_bytes)
    system_info.read(result['lpSystemInfo'])

    version_info = OsVersionInfoExA.new
    version_info.os_version_info_size = version_info.num_bytes
    result = session.railgun.kernel32.GetVersionExA(version_info.to_binary_s)
    version_info.read(result['lpVersionInformation'])

    minidump_system_info = MinidumpSystemInfo.new(
      :processor_architecture => system_info.processor_architecture,
      :processor_level => system_info.processor_level,
      :processor_revision => system_info.processor_revision,
      :number_of_processors => system_info.number_of_processors,
      :product_type => version_info.product_type,
      :major_version => version_info.major_version,
      :minor_version => version_info.minor_version,
      :build_number => version_info.build_number,
      :platform_id => version_info.platform_id,
      :suite_mask => version_info.suite_mask
    )

    {:stream => minidump_system_info, :type => 7}
  end

  def write_minidump(file_path)
    streams = []
    streams << get_stream_minidump_system_info

    file_h = File.open(file_path, 'wb')
    header = MinidumpHeader.new(
      :signature => 0x504d444d,
      :version => 0x6380a793,
      :number_of_streams => streams.length
    )
    header.rva = header.num_bytes
    file_h.write(header.to_binary_s)
    cursor = header.rva
    stream_cursor = cursor

    minidump_directory_size = MinidumpDirectory.new.num_bytes

    streams.each_with_index do |stream_info, index|
      minidump_directory = MinidumpDirectory.new(:stream_type => stream_info[:type])
      minidump_directory.location.assign(
        :data_size => stream_info[:stream].num_bytes,
        :rva => (stream_cursor + (minidump_directory_size * streams.length))
      )
      vprint_status("Minidump: Adding directory (type: #{minidump_directory.stream_type} size: #{minidump_directory.location.data_size} rva: #{minidump_directory.location.rva})")
      stream_cursor += minidump_directory.location.data_size
      file_h.write(minidump_directory.to_binary_s)
    end

    streams.each do |stream_info|
      file_h.write(stream_info[:stream].to_binary_s)
    end

    file_h.close
  end

end # Minidump
end # Windows
end # Post
end # Msf
