rnvs_proto = Proto("rnvs", "RNVS Protocol")

flags_f = ProtoField.uint8("rnvs.flags", "flags", base.HEX)

key_length_f = ProtoField.uint16("rnvs.key_length", "keyLength", base.DEC)
value_length_f = ProtoField.uint32("rnvs.value_length", "valueLength", base.DEC)
key_f = ProtoField.bytes("rnvs.key", "key", base.DOT)
value_f = ProtoField.bytes("rnvs.value", "value", base.DOT)

hash_id_f = ProtoField.uint16("rnvs.hash_id", "hashId", base.HEX)
node_id_f = ProtoField.uint16("rnvs.node_id", "nodeId", base.HEX)
node_ip_f = ProtoField.ipv4("rnvs.node_id", "nodeIP")
node_port_f = ProtoField.uint16("rnvs.node_id", "nodePort", base.DEC)

rnvs_proto.fields = { flags_f,
    key_length_f, value_length_f, key_f, value_f,
    hash_id_f, node_id_f, node_ip_f, node_port_f
}


function get_flag_names(val)
    flags = {}
    if bit32.band(val, 1) ~= 0 then table.insert(flags, "Delete") end
    if bit32.band(val, 2) ~= 0 then table.insert(flags, "Set") end
    if bit32.band(val, 4) ~= 0 then table.insert(flags, "Get") end
    if bit32.band(val, 8) ~= 0 then table.insert(flags, "Ack") end
    return table.concat(flags, ", ")
end

function get_control_name(val)
    flags = {}
    if bit32.band(val, 1) ~= 0 then table.insert(flags, "Lookup") end
    if bit32.band(val, 2) ~= 0 then table.insert(flags, "Reply") end
    return table.concat(flags, ", ")
end

function rnvs_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = rnvs_proto.name

    local subtree = tree:add(rnvs_proto, buffer(), "RNVS Protocol, Len: " .. length)

    flags  = buffer(0, 1)
    if bit32.band(flags:uint(), 0x80) == 0 then
        header_length = 7
        if length < header_length then
            pinfo.desegment_len = header_length - length
            pinfo.desegment_offset = 0
            return
        end
    end

    flags  = buffer(0, 1)
    if bit32.band(flags:uint(), 0x80) == 0 then
        subtree:add(flags_f, flags):append_text(" (" .. get_flag_names(flags:uint()) .. ")")
        local key_length = buffer(1, 2)
        subtree:add(key_length_f, key_length)

        local value_length = buffer(3, 4)
        subtree:add(value_length_f, value_length)

        local total_length = header_length + key_length:uint() + value_length:uint()
        if length < total_length then
            pinfo.desegment_len = total_length - length
            pinfo.desegment_offset = 0
            return
        end

        subtree:add(key_f, buffer(header_length, key_length:uint()))
        subtree:add(value_f, buffer(header_length + key_length:uint(), value_length:uint()))

        return header_length + key_length:uint() + value_length:uint()
    else
        if length < 11 then
            pinfo.desegment_len = 11 - length
            pinfo.desegment_offset = 0
            return
        end

        subtree:add(flags_f, flags):append_text(" (" .. get_control_name(flags:uint()) .. ")")
        subtree:add(hash_id_f, buffer(1, 2))
        subtree:add(node_id_f, buffer(3, 2))
        subtree:add(node_ip_f, buffer(5, 4))
        subtree:add(node_port_f, buffer(9, 2))

        return 11
    end
end

rnvs_proto:register_heuristic("tcp", rnvs_proto.dissector)
