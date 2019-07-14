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

local FLAG_STRINGS = {[0] = "Not set", [1] = "Set"}

-- See: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
f_version  = ProtoField.uint8("mut_v1.version", "Version", base.DEC, nil, 0xf0)
f_flag_psh = ProtoField.uint8("mut_v1.flag_psh", "PSH Flag", base.DEC, FLAG_STRINGS, 0x4)
f_flag_ack = ProtoField.uint8("mut_v1.flag_ack", "ACK Flag", base.DEC, FLAG_STRINGS, 0x2)
f_flag_syn = ProtoField.uint8("mut_v1.flag_syn", "SYN Flag", base.DEC, FLAG_STRINGS, 0x1)
f_sequence = ProtoField.uint24("mut_v1.sequence", "Sequence", base.HEX_DEC)
protocol.fields = { f_version, f_flag_psh, f_flag_ack, f_flag_syn, f_sequence }

function protocol.dissector(buffer, pinfo, tree)
    -- Check for the minimum buffer length required to process this frame
    if buffer:len() < 4 then return end

    -- Check that the version number is 1 before proceeding
    local version = bit.rshift(bit.band(buffer(0,1):uint(), 0xf0), 4)
    if version ~= 1 then return end

    pinfo.cols.protocol = protocol.name

    local subtree = tree:add(protocol, buffer(), protocol.description)
    subtree:add(f_version, buffer(0, 1))
    subtree:add(f_flag_psh, buffer(0, 1))
    subtree:add(f_flag_ack, buffer(0, 1))
    subtree:add(f_flag_syn, buffer(0, 1))
    subtree:add(f_sequence, buffer(1, 3))
end

-- Register the protocol to handle UDP port 4444
udp_table = DissectorTable.get("udp.port")
udp_table:add(4444, protocol)
