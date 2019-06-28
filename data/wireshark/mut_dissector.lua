--
-- A wireshark dissector for the Metasploit UDP Transport v1 (MUTv1) Protocol.
-- This is mostly useful for debugging purposes.
--
-- Load with: wireshark -X lua_script:mut_dissector.lua
--
-- Format specification:
--   0                   1                   2                   3
--   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--  |Version|R|P|A|S|                    Sequence                   |
--  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--

protocol = Proto("MUT_v1", "Metasploit UDP Transport v1")

function protocol.dissector(buffer, pinfo, tree)
    if buffer:len() < 4 then return end

    local header = buffer(0,1):uint()
    local version = bit.rshift(bit.band(header, 0xf0), 4)
    if version ~= 1 then return end

    pinfo.cols.protocol = protocol.name
    local subtree = tree:add(protocol, buffer(), protocol.description)

    subtree:add(buffer(0,1), "Version: " .. tostring(version))

    subtree:add(buffer(0,1), "Flag (PSH): " .. (bit.band(header, 0x4) == 0 and 'False' or 'True'))
    subtree:add(buffer(0,1), "Flag (ACK): " .. (bit.band(header, 0x2) == 0 and 'False' or 'True'))
    subtree:add(buffer(0,1), "Flag (SYN): " .. (bit.band(header, 0x1) == 0 and 'False' or 'True'))

    subtree:add(buffer(1,3), "Sequence: " .. tostring(buffer(1,3):uint()))
end

-- Register the protocol to handle UDP port 4444
udp_table = DissectorTable.get("udp.port")
udp_table:add(4444, protocol)
