from typing import List
from microschc.binary.buffer import Buffer, Padding
from microschc.compressor.compressor import _compact_left, _encode_length, compress
from microschc.parser.factory import factory
from microschc.parser.parser import PacketParser
from microschc.parser.protocol.coap import CoAPFields
from microschc.parser.protocol.ipv6 import IPv6Fields
from microschc.parser.protocol.udp import UDPFields
from microschc.rfc8724 import DirectionIndicator, MatchMapping, PacketDescriptor, RuleDescriptor, RuleFieldDescriptor
from microschc.rfc8724extras import ParserDefinitions, StacksImplementation
from microschc.rfc8724 import MatchingOperator as MO
from microschc.rfc8724 import CompressionDecompressionAction as CDA


def test_compress():

    valid_stack_packet:bytes = bytes(
        b"\x60\x00\xef\x2d\x00\x68\x11\x40\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
        b"\x00\x00\x00\x00\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
        b"\x00\x00\x00\x00\x00\x00\x00\x20\xd1\x00\x16\x33\x00\x68\x5c\x21" \
        b"\x68\x45\x22\xf6\xb8\x30\x0e\xfe\xe6\x62\x91\x22\xc1\x6e\xff\x5b" \
        b"\x7b\x22\x62\x6e\x22\x3a\x22\x2f\x36\x2f\x22\x2c\x22\x6e\x22\x3a" \
        b"\x22\x30\x2f\x30\x22\x2c\x22\x76\x22\x3a\x35\x34\x2e\x30\x7d\x2c" \
        b"\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x31\x22\x2c\x22\x76\x22\x3a\x34" \
        b"\x38\x2e\x30\x7d\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x35\x22\x2c" \
        b"\x22\x76\x22\x3a\x31\x36\x36\x36\x32\x36\x33\x33\x33\x39\x7d\x5d"
    )

    packet_parser: PacketParser = factory(stack_implementation=StacksImplementation.IPV6_UDP_COAP)
    packet_descriptor: PacketDescriptor = packet_parser.parse(buffer=valid_stack_packet, direction=DirectionIndicator.UP)

    field_descriptors_1: List[RuleFieldDescriptor] = [
        RuleFieldDescriptor(
            id=IPv6Fields.VERSION, length=4, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'\x06', bit_length=4), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.TRAFFIC_CLASS, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'\x00', bit_length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.FLOW_LABEL, length=20, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x00\xef\x2d', bit_length=20), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.PAYLOAD_LENGTH, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL, 
            target_value=Buffer(content=b'', bit_length=16), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.NEXT_HEADER, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x11', bit_length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.HOP_LIMIT, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x40', bit_length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(
            id=IPv6Fields.SRC_ADDRESS, length=128, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00', bit_length=120), 
            matching_operator=MO.MSB, compression_decompression_action=CDA.LSB),
        RuleFieldDescriptor(id=IPv6Fields.DST_ADDRESS, length=128, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=MatchMapping(forward_mapping={
                Buffer(content=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20", bit_length=128):Buffer(content=b'\x00', bit_length=2)
            }), 
            matching_operator=MO.MATCH_MAPPING, compression_decompression_action=CDA.MAPPING_SENT),

        RuleFieldDescriptor(id=UDPFields.SOURCE_PORT, length=16, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\xd1\x00', bit_length=16), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=UDPFields.DESTINATION_PORT, length=16, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x16\x33', bit_length=16), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=UDPFields.LENGTH, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=UDPFields.CHECKSUM, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),

        RuleFieldDescriptor(id=CoAPFields.VERSION, length=2, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x01', bit_length=2), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=CoAPFields.TYPE, length=2, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'\x02', bit_length=2), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=CoAPFields.TOKEN_LENGTH, length=4, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.CODE, length=8, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.MESSAGE_ID, length=16, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.TOKEN, length=0, position=0, direction=DirectionIndicator.BIDIRECTIONAL,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.OPTION_DELTA, length=4, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\x0c', bit_length=0), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=CoAPFields.OPTION_LENGTH, length=4, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.OPTION_VALUE, length=0, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT),
        RuleFieldDescriptor(id=CoAPFields.PAYLOAD_MARKER, length=8, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'\xff', bit_length=8), matching_operator=MO.EQUAL, compression_decompression_action=CDA.NOT_SENT),
        RuleFieldDescriptor(id=ParserDefinitions.PAYLOAD, length=0, position=0, direction=DirectionIndicator.UP,
            target_value=Buffer(content=b'', bit_length=0), matching_operator=MO.IGNORE, compression_decompression_action=CDA.VALUE_SENT)
    ]
    rule_descriptor_1: RuleDescriptor = RuleDescriptor(id=Buffer(content=b'\x03', bit_length=2), field_descriptors=field_descriptors_1)

    schc_packet = compress(packet_descriptor=packet_descriptor, rule_descriptor=rule_descriptor_1)
    schc_packet = _compact_left(buffer=schc_packet, bytefield=packet_descriptor.payload)
    assert schc_packet == Buffer(content= b'\xc0\x1a\x00\x80\x06\x85\xc2\x18\x45\x22\xf6\xf4' \
                                          b'\x0b\x83\x00\xef\xee\x66\x29\x12\x21\x86\xe5\xb7' \
                                          b'\xb2\x26\x26\xe2\x23\xa2\x22\xf3\x62\xf2\x22\xc2' \
                                          b'\x26\xe2\x23\xa2\x23\x02\xf3\x02\x22\xc2\x27\x62' \
                                          b'\x23\xa3\x53\x42\xe3\x07\xd2\xc7\xb2\x26\xe2\x23' \
                                          b'\xa2\x23\x02\xf3\x12\x22\xc2\x27\x62\x23\xa3\x43' \
                                          b'\x82\xe3\x07\xd2\xc7\xb2\x26\xe2\x23\xa2\x23\x02' \
                                          b'\xf3\x52\x22\xc2\x27\x62\x23\xa3\x13\x63\x63\x63' \
                                          b'\x23\x63\x33\x33\x33\x97\xd5\xd0',
                                 bit_length=828, padding_side=Padding.RIGHT)


def test_encode_length():
    
    # test #1: length = 5
    length: int = 5
    expected_encoded_length: bytes = b'\x05'
    expected_encoded_length_length: int = 4
    encoded_length: Buffer = _encode_length(length=length)

    assert encoded_length.content == expected_encoded_length
    assert encoded_length.bit_length == expected_encoded_length_length


    # test #2: length = 14
    length: int = 14
    expected_encoded_length: bytes = b'\x0e'
    expected_encoded_length_length: int = 4
    encoded_length: Buffer = _encode_length(length=length)

    assert encoded_length.content == expected_encoded_length
    assert encoded_length.bit_length == expected_encoded_length_length

    # test #3: length = 15
    length: int = 15
    expected_encoded_length: bytes = b'\x0f\x0f'
    expected_encoded_length_length: int = 12
    encoded_length: Buffer = _encode_length(length=length)

    assert encoded_length.content == expected_encoded_length
    assert encoded_length.bit_length == expected_encoded_length_length

    # test #4: length = 254
    length: int = 254
    expected_encoded_length: bytes = b'\x0f\xfe'
    expected_encoded_length_length: int = 12
    encoded_length: Buffer = _encode_length(length=length)

    assert encoded_length.content == expected_encoded_length
    assert encoded_length.bit_length == expected_encoded_length_length

    # test #5: length = 255
    length: int = 255
    expected_encoded_length: bytes = b'\x0f\xff\x00\xff'
    expected_encoded_length_length: int = 28
    encoded_length: Buffer = _encode_length(length=length)

    assert encoded_length.content == expected_encoded_length
    assert encoded_length.bit_length == expected_encoded_length_length

    # test #6: length = 65535
    length: int = 65535
    expected_encoded_length: bytes = b'\x0f\xff\xff\xff'
    expected_encoded_length_length: int = 28
    encoded_length: Buffer = _encode_length(length=length)

    assert encoded_length.content == expected_encoded_length
    assert encoded_length.bit_length == expected_encoded_length_length



def test_compact_left():

    # test #1: bytefield needs 1 bit left shifting before concatenation
    # 
    #                             buffer                                                  bytefield
    #       |-----------------------------------------------|         |-----------------------------------------------|
    #                                     offset   trailing
    #                                         = 3  zeros = 5          offset = 4
    #       |-------------------------------|-----|---------|   +     |-------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0           0 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1
    #       |     byte0     |   byte1       |     byte2     |         |    byte 0     |    byte 1     |    byte 2     |
    #              0x33           0xff            0x60                      0x0c            0x33            0xff
    #                                                          =
    #       |              old buffer                            bytefield               offset
    #       |-------------------------------------|---------------------------------------|-|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0
    #       |     byte0     |   byte1       |     byte2     |     byte3     |     byte4     |
    #             0x33            0xff            0x78            0x67             0xfe
    buffer: Buffer = Buffer(content=b'\x33\xff\x60', bit_length=19, padding_side=Padding.RIGHT)
    bytefield: Buffer = Buffer(content=b'\x0c\x33\xff', bit_length=20, padding_side=Padding.LEFT)
    expected_buffer: Buffer = Buffer(content=b'\x33\xff\x78\x67\xfe', bit_length=39, padding_side=Padding.RIGHT)
    compacted = _compact_left(buffer=buffer, bytefield=bytefield)
    assert compacted == expected_buffer

    
    # test #2: bytefield needs 2 bits right shifting before concatenation
    # 
    #                             buffer                                                  bytefield
    #       |-----------------------------------------------|         |-----------------------------------------------|
    #                                     offset   trailing
    #                                         = 6  zeros = 2          offset = 4
    #       |-------------------------------|-----------|---|   +     |-------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0           0 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1
    #       |     byte0     |   byte1       |     byte2     |         |    byte 0     |    byte 1     |    byte 2     |
    #              0x33           0xff            0x60                      0x0c            0x33            0xff
    #                                                          =
    #       |              old buffer                            bytefield                         offset
    #       |-------------------------------------------|---------------------------------------|-----------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0
    #       |     byte0     |   byte1       |     byte2     |     byte3     |     byte4     |     byte5     |
    #             0x33            0xff            0x63            0x0c             0xff             0xc0
    buffer = Buffer(content=b'\x33\xff\x60', bit_length=22, padding_side=Padding.RIGHT)
    bytefield = Buffer(content=b'\x0c\x33\xff', bit_length=20, padding_side=Padding.LEFT)
    expected_buffer = Buffer(content=b'\x33\xff\x63\x0c\xff\xc0', bit_length=42, padding_side=Padding.RIGHT)
    compacted = _compact_left(buffer=buffer, bytefield=bytefield)
    assert compacted == expected_buffer

    # test #3: bytefield and buffer have the same non-zero offset
    # 
    #                             buffer                                                  bytefield
    #       |-----------------------------------------------|         |-----------------------------------------------|
    #                                     offset   trailing
    #                                         = 4  zeros = 4          offset = 4
    #       |-------------------------------|-------|-------|   +     |-------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0           0 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1
    #       |     byte0     |   byte1       |     byte2     |         |    byte 0     |    byte 1     |    byte 2     |
    #              0x33           0xff            0x60                      0x0c            0x33            0xff
    #                                                          =
    #       |              old buffer                            bytefield                   
    #       |---------------------------------------|---------------------------------------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1
    #       |     byte0     |   byte1       |     byte2     |     byte3     |     byte4     |
    #             0x33            0xff            0x6c            0x33             0xff      
    buffer: Buffer = Buffer(content=b'\x33\xff\x60', bit_length=20, padding_side=Padding.RIGHT)
    bytefield = Buffer(content=b'\x0c\x33\xff', bit_length=20, padding_side=Padding.LEFT)
    expected_buffer: Buffer = Buffer(content=b'\x33\xff\x6c\x33\xff', bit_length=40, padding_side=Padding.RIGHT)
    compacted = _compact_left(buffer=buffer, bytefield=bytefield)
    assert compacted == expected_buffer

    # test #4: bytefield and buffer have the same zero offset
    # 
    #                             buffer                                                  bytefield
    #       |-----------------------------------------------|         |-----------------------------------------------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0           0 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1
    #       |     byte0     |   byte1       |     byte2     |         |    byte 0     |    byte 1     |    byte 2     |
    #              0x33           0xff            0x60                      0x0c            0x33            0xff
    #                                                          =
    #                             buffer                                         bytefield
    #       |-----------------------------------------------|-----------------------------------------------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0 0 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1
    #       |     byte0     |   byte1       |     byte2     |    byte 3     |    byte 4     |    byte 5     |
    #              0x33           0xff            0x60            0x0c            0x33            0xff
    
    buffer: Buffer = Buffer(content=b'\x33\xff\x60', bit_length=24, padding_side=Padding.RIGHT)
    bytefield: Buffer = Buffer(content=b'\x0c\x33\xff', bit_length=24, padding_side=Padding.LEFT)
    expected_buffer: Buffer = Buffer(content=b'\x33\xff\x60\x0c\x33\xff', bit_length=48, padding_side=Padding.RIGHT)
    compacted = _compact_left(buffer=buffer, bytefield=bytefield)
    assert compacted == expected_buffer

    # test #5: bytefield needs 2 bits left shifting and buffer has zero offset
    # 
    #                             buffer                                                  bytefield
    #       |-----------------------------------------------|         |-----------------------------------------------|
    #                                                               offset = 2
    #                                                                 |---|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0           0 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1
    #       |     byte0     |   byte1       |     byte2     |         |    byte 0     |    byte 1     |    byte 2     |
    #              0x33           0xff            0x60                      0x0c            0x33            0xff
    #                                                          =
    #                             buffer                                         bytefield
    #       |-----------------------------------------------|-----------------------------------------------|
    #        0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 0 0 0 0 0 0 0 1 1 0 0 0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0
    #       |     byte0     |   byte1       |     byte2     |    byte 3     |    byte 4     |    byte 5     |
    #              0x33           0xff            0x60            0x30            0xcf            0xfc
    
    buffer: Buffer = Buffer(content=b'\x33\xff\x60', bit_length=24, padding_side=Padding.RIGHT)
    bytefield: Buffer = Buffer(content=b'\x0c\x33\xff', bit_length=22, padding_side=Padding.LEFT)
    expected_buffer: Buffer = Buffer(content=b'\x33\xff\x60\x30\xcf\xfc', bit_length=46, padding_side=Padding.RIGHT)
    compacted = _compact_left(buffer=buffer, bytefield=bytefield)
    assert compacted == expected_buffer