from io import BytesIO
import struct
from enum import Enum
from microschc.binary.buffer import Buffer
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor
from microschc.parser.parser import HeaderParser

from microschc.external.test_crypto import convert_aux_sec_hdr_to_bytearray
import microschc.external.mle as mle
from microschc.external.config import create_default_thread_message_factory, DEFAULT_NETWORK_KEY


Thread_HEADER_ID = 'Thread'

Thread_IPv6_HEADER_ID = 'IPv6'
class ThreadIPv6Fields(str, Enum):
    VERSION         = f'{Thread_IPv6_HEADER_ID}:Version'
    TRAFFIC_CLASS   = f'{Thread_IPv6_HEADER_ID}:Traffic Class'
    FLOW_LABEL      = f'{Thread_IPv6_HEADER_ID}:Flow Label'
    PAYLOAD_LENGTH  = f'{Thread_IPv6_HEADER_ID}:Payload Length'
    NEXT_HEADER     = f'{Thread_IPv6_HEADER_ID}:Next Header'
    HOP_LIMIT       = f'{Thread_IPv6_HEADER_ID}:Hop Limit'
    SRC_ADDRESS     = f'{Thread_IPv6_HEADER_ID}:Source Address'
    DST_ADDRESS     = f'{Thread_IPv6_HEADER_ID}:Destination Address'


Thread_UDP_HEADER_ID = 'UDP'
class ThreadUDPFields(str, Enum):
    SOURCE_PORT         = f'{Thread_UDP_HEADER_ID}:Source Port'
    DESTINATION_PORT    = f'{Thread_UDP_HEADER_ID}:Destination Port'
    LENGTH              = f'{Thread_UDP_HEADER_ID}:Length'
    CHECKSUM            = f'{Thread_UDP_HEADER_ID}:Checksum'

Thread_ICMP_HEADER_ID = 'ICMP'
class ThreadICMPFields(str, Enum):
    TYPE                  = f'{Thread_ICMP_HEADER_ID}:Type'
    CODE                  = f'{Thread_ICMP_HEADER_ID}:Code'
    CHECKSUM              = f'{Thread_ICMP_HEADER_ID}:Checksum'
    IDENTIFIER            = f'{Thread_ICMP_HEADER_ID}:Identifier'
    SEQUENCE              = f'{Thread_ICMP_HEADER_ID}:Sequence'


Thread_COAP_HEADER_ID = 'CoAP'
class ThreadCoAPFields(str, Enum):
    VERSION                 = f'{Thread_COAP_HEADER_ID}:Version'
    TYPE                    = f'{Thread_COAP_HEADER_ID}:Type'
    TOKEN_LENGTH            = f'{Thread_COAP_HEADER_ID}:Token Length'
    CODE                    = f'{Thread_COAP_HEADER_ID}:Code'
    MESSAGE_ID              = f'{Thread_COAP_HEADER_ID}:Message ID'
    TOKEN                   = f'{Thread_COAP_HEADER_ID}:Token'
    OPTION_DELTA            = f'{Thread_COAP_HEADER_ID}:Option Delta'
    OPTION_LENGTH           = f'{Thread_COAP_HEADER_ID}:Option Length'
    OPTION_VALUE            = f'{Thread_COAP_HEADER_ID}:Option Value'
    PAYLOAD_MARKER          = f'{Thread_COAP_HEADER_ID}:Payload Marker'
    PAYLOAD                 = f'{Thread_COAP_HEADER_ID}:Payload'



Thread_MLE_HEADER_ID = 'MLE'
class ThreadMLEFields(str, Enum):
    SECURITY_INDICATOR              = f'{Thread_MLE_HEADER_ID}:Security indicator'
    AUX_SEC_HEADER                  = f'{Thread_MLE_HEADER_ID}:Aux Sec Header'
    COMMANDE                        = f'{Thread_MLE_HEADER_ID}:Commande'
    MIC                             = f'{Thread_MLE_HEADER_ID}:MIC'

    #TLVs
    TLV_SOURCE_ADDRESS              = f'{Thread_MLE_HEADER_ID}:TLV Source Address'
    TLV_MODE                        = f'{Thread_MLE_HEADER_ID}:TLV Mode'
    TLV_TIMEOUT                     = f'{Thread_MLE_HEADER_ID}:TLV Timeout'
    TLV_CHALLENGE                   = f'{Thread_MLE_HEADER_ID}:TLV Challenge'
    TLV_RESPONSE                    = f'{Thread_MLE_HEADER_ID}:TLV Response'
    TLV_LINK_LAYER_FRAME_COUNTER    = f'{Thread_MLE_HEADER_ID}:TLV Link Layer Frame Counter'
    TLV_MLE_FRAME_COUNTER           = f'{Thread_MLE_HEADER_ID}:TLV MLE Frame Counter'
    TLV_ROUTE64                     = f'{Thread_MLE_HEADER_ID}:TLV Route64'
    TLV_ADDRESS16                   = f'{Thread_MLE_HEADER_ID}:TLV Address16'
    TLV_LEADER_DATA                 = f'{Thread_MLE_HEADER_ID}:TLV Leader Data'
    TLV_NETWORK_DATA                = f'{Thread_MLE_HEADER_ID}:TLV Network Data'
    TLV_REQUEST                     = f'{Thread_MLE_HEADER_ID}:TLV Request'
    TLV_SCAN_MASK                   = f'{Thread_MLE_HEADER_ID}:TLV Scan Mask'
    TLV_CONNECTIVITY                = f'{Thread_MLE_HEADER_ID}:TLV Connectivity'
    TLV_LINK_MARGIN                 = f'{Thread_MLE_HEADER_ID}:TLV Link Margin'
    TLV_STATUS                      = f'{Thread_MLE_HEADER_ID}:TLV Status'
    TLV_VERSION                     = f'{Thread_MLE_HEADER_ID}:TLV Version'
    TLV_ADDRESS_REGISTRATION        = f'{Thread_MLE_HEADER_ID}:TLV Address Registration'
    TLV_CHANNEL                     = f'{Thread_MLE_HEADER_ID}:TLV Channel'
    TLV_PANID                       = f'{Thread_MLE_HEADER_ID}:TLV PanID'
    TLV_ACTIVE_TIMESTAMP            = f'{Thread_MLE_HEADER_ID}:TLV Active Timestamp'
    TLV_PENDING_TIMESTAMP           = f'{Thread_MLE_HEADER_ID}:TLV Pending Timestamp'
    TLV_ACTIVE_OP_DATASET           = f'{Thread_MLE_HEADER_ID}:TLV Active Operational Dataset'
    TLV_PENDING_OP_DATASET          = f'{Thread_MLE_HEADER_ID}:TLV Pending Operational Dataset'
    TLV_THREAD_DISCOVERY            = f'{Thread_MLE_HEADER_ID}:TLV Thread Discovery'

    TLV_SUPERVISION_INTERVAL        = f'{Thread_MLE_HEADER_ID}:TLV Supervision Interval'
    TLV_CSL_CLOCK_ACCURACY          = f'{Thread_MLE_HEADER_ID}:TLV CSL Clock Accuracy'

# Mapping of TLVs
tlv_field_map = {
    mle.SourceAddress           : ThreadMLEFields.TLV_SOURCE_ADDRESS,
    mle.Mode                    : ThreadMLEFields.TLV_MODE,
    mle.Timeout                 : ThreadMLEFields.TLV_TIMEOUT,
    mle.Challenge               : ThreadMLEFields.TLV_CHALLENGE,
    mle.Response                : ThreadMLEFields.TLV_RESPONSE,
    mle.LinkLayerFrameCounter   : ThreadMLEFields.TLV_LINK_LAYER_FRAME_COUNTER,
    mle.MleFrameCounter         : ThreadMLEFields.TLV_MLE_FRAME_COUNTER,
    mle.Route64                 : ThreadMLEFields.TLV_ROUTE64,
    mle.Address16               : ThreadMLEFields.TLV_ADDRESS16,
    mle.LeaderData              : ThreadMLEFields.TLV_LEADER_DATA,
    mle.NetworkData             : ThreadMLEFields.TLV_NETWORK_DATA,
    mle.TlvRequest              : ThreadMLEFields.TLV_REQUEST,
    mle.ScanMask                : ThreadMLEFields.TLV_SCAN_MASK,
    mle.Connectivity            : ThreadMLEFields.TLV_CONNECTIVITY,
    mle.LinkMargin              : ThreadMLEFields.TLV_LINK_MARGIN,
    mle.Status                  : ThreadMLEFields.TLV_STATUS,
    mle.Version                 : ThreadMLEFields.TLV_VERSION,
    mle.AddressRegistration     : ThreadMLEFields.TLV_ADDRESS_REGISTRATION,
    mle.Channel                 : ThreadMLEFields.TLV_CHANNEL,
    mle.PanId                   : ThreadMLEFields.TLV_PANID,
    mle.ActiveTimestamp         : ThreadMLEFields.TLV_ACTIVE_TIMESTAMP,
    mle.PendingTimestamp        : ThreadMLEFields.TLV_PENDING_TIMESTAMP,
    mle.ThreadDiscovery         : ThreadMLEFields.TLV_THREAD_DISCOVERY,
    mle.ActiveOperationalDataset : ThreadMLEFields.TLV_ACTIVE_OP_DATASET,
    mle.PendingOperationalDataset: ThreadMLEFields.TLV_PENDING_OP_DATASET,

    mle.SupervisionInterval      : ThreadMLEFields.TLV_SUPERVISION_INTERVAL,
    mle.CslClockAccuracy         : ThreadMLEFields.TLV_CSL_CLOCK_ACCURACY
}

# Next headers for IPv6 protocols
IPV6_NEXT_HEADER_HOP_BY_HOP = 0
IPV6_NEXT_HEADER_TCP = 6
IPV6_NEXT_HEADER_UDP = 17
IPV6_NEXT_HEADER_FRAGMENT = 44
IPV6_NEXT_HEADER_ICMP = 58

# Message types 
MLE = 0
COAP = 1
ICMP = 2
ACK = 3
BEACON = 4
DATA = 5
COMMAND = 6
DTLS = 7
   

class ThreadParser(HeaderParser):

    def __init__(self, interpret_options=False) -> None:
        super().__init__(name=Thread_HEADER_ID)
        
    def parse(self, buffer: Buffer) -> HeaderDescriptor:
        header_descriptor:HeaderDescriptor = HeaderDescriptor(id=Thread_HEADER_ID, length=0, fields=[])
        message_factory = create_default_thread_message_factory(network_key=DEFAULT_NETWORK_KEY)
        message = message_factory.create(BytesIO(buffer.content))

        if hasattr(message, 'mac_header'):
            # Take only mac frame data packets, not beacon ack and command, no fragments
            if message.mac_header.frame_type == 1: # DATA = 1
                version = (message.ipv6_packet.ipv6_header.version & 0x0F).to_bytes(1, 'big')
                traffic_class_flow_label = (message.ipv6_packet.ipv6_header.traffic_class << 20) | message.ipv6_packet.ipv6_header.flow_label
                traffic_class = ((traffic_class_flow_label >> 20) & 0xFF).to_bytes(1, 'big')
                flow_label = (traffic_class_flow_label & 0xFFFFF).to_bytes(3, 'big')

                payload_length  = struct.pack(">H", (message.ipv6_packet.ipv6_header.payload_length))
                next_header     = (message.ipv6_packet.ipv6_header.next_header).to_bytes(1, 'big')
                hop_limit       = (message.ipv6_packet.ipv6_header.hop_limit).to_bytes(1, 'big')
                source_address  = message.ipv6_packet.ipv6_header.source_address.packed
                destination_address = message.ipv6_packet.ipv6_header.destination_address.packed
                
                header_descriptor.fields.extend([
                        FieldDescriptor(id=ThreadIPv6Fields.VERSION,         position=0, value=Buffer(version,              4)),
                        FieldDescriptor(id=ThreadIPv6Fields.TRAFFIC_CLASS,   position=0, value=Buffer(traffic_class,        8)),
                        FieldDescriptor(id=ThreadIPv6Fields.FLOW_LABEL,      position=0, value=Buffer(flow_label,           20)),
                        FieldDescriptor(id=ThreadIPv6Fields.PAYLOAD_LENGTH,  position=0, value=Buffer(payload_length,       16)),
                        FieldDescriptor(id=ThreadIPv6Fields.NEXT_HEADER,     position=0, value=Buffer(next_header,          8)),
                        FieldDescriptor(id=ThreadIPv6Fields.HOP_LIMIT,       position=0, value=Buffer(hop_limit,            8)),
                        FieldDescriptor(id=ThreadIPv6Fields.SRC_ADDRESS,     position=0, value=Buffer(source_address,       128)),
                        FieldDescriptor(id=ThreadIPv6Fields.DST_ADDRESS,     position=0, value=Buffer(destination_address,  128))
                        ])
                header_descriptor.length += 320
                        
                # Take only MLE, Coap ICMP messages
                if message.type == ICMP:
                    icmp_type   = struct.pack("B", message.icmp.header.type)
                    code        = struct.pack("B", message.icmp.header.code)
                    checksum    = struct.pack(">H", message.icmp.header.checksum)
      
                    # Don't save the data payload
                    header_descriptor.fields.extend([
                        FieldDescriptor(id=ThreadICMPFields.TYPE,          position=0, value=Buffer(icmp_type,  8)),
                        FieldDescriptor(id=ThreadICMPFields.CODE,          position=0, value=Buffer(code,       8)),
                        FieldDescriptor(id=ThreadICMPFields.CHECKSUM,      position=0, value=Buffer(checksum,   16))
                    ])
                    
                    # Add identifier and sequence number if they are present
                    if hasattr(message.icmp.body, 'identifier') and hasattr(message.icmp.body, 'sequence_number'):
                        identifier  = struct.pack(">H", message.icmp.body.identifier)
                        sequence    = struct.pack(">H", message.icmp.body.sequence_number)
                        header_descriptor.fields.extend([
                            FieldDescriptor(id=ThreadICMPFields.IDENTIFIER,  position=0, value=Buffer(identifier, 16)),
                            FieldDescriptor(id=ThreadICMPFields.SEQUENCE,    position=0, value=Buffer(sequence,   16))
                        ])
                        header_descriptor.length += 64
                    else:
                        header_descriptor.length += 32

                # UDP or hop  by hop, no fragments, no tcp packets
                elif (message.ipv6_packet.ipv6_header.next_header == IPV6_NEXT_HEADER_UDP) or (message.ipv6_packet.ipv6_header.next_header == IPV6_NEXT_HEADER_HOP_BY_HOP):
                    src_port           = struct.pack(">H", message.ipv6_packet.upper_layer_protocol.header.src_port)
                    dst_port           = struct.pack(">H", message.ipv6_packet.upper_layer_protocol.header.dst_port)
                    udp_payload_length = struct.pack(">H", message.ipv6_packet.upper_layer_protocol.header.payload_length)
                    udp_checksum       = struct.pack(">H", message.ipv6_packet.upper_layer_protocol.header.checksum)

                    header_descriptor.fields.extend([
                        FieldDescriptor(id=ThreadUDPFields.SOURCE_PORT,       position=0, value=Buffer(src_port,            16)),
                        FieldDescriptor(id=ThreadUDPFields.DESTINATION_PORT,  position=0, value=Buffer(dst_port,            16)),
                        FieldDescriptor(id=ThreadUDPFields.LENGTH,            position=0, value=Buffer(udp_payload_length,  16)),
                        FieldDescriptor(id=ThreadUDPFields.CHECKSUM,          position=0, value=Buffer(udp_checksum,        16))
                    ])
                    header_descriptor.length += 64

                    # Only MLE and coap messages, no ack, beacon, data, command or dtls
                    if message.type == MLE:
                        security_indicator = message.mle.security_indicator.to_bytes(1, 'big')
                        aux_sec_hdr_bytes = convert_aux_sec_hdr_to_bytearray(message.mle.aux_sec_hdr)
                        command_bytes = message.mle.command.commande_to_bytes()
                        mic_bytes = message.mle.mic

                        header_descriptor.fields.extend([
                            FieldDescriptor(id=ThreadMLEFields.SECURITY_INDICATOR,  position=0, value=Buffer(security_indicator, 8)),
                            FieldDescriptor(id=ThreadMLEFields.AUX_SEC_HEADER,      position=0, value=Buffer(aux_sec_hdr_bytes, len(aux_sec_hdr_bytes) * 8)),
                            FieldDescriptor(id=ThreadMLEFields.COMMANDE,            position=0, value=Buffer(command_bytes,     len(command_bytes) * 8)),
                        ])
                        # Dynamically handle each TLV
                        offset = sum([len(security_indicator), len(aux_sec_hdr_bytes), len(command_bytes), len(mic_bytes)]) * 8
                        for tlv in message.mle.command.tlvs:
                            tlv_type = type(tlv)
                            if tlv_type in tlv_field_map:
                                tlv_bytes = tlv.to_bytes()
                                tlv_bit_length = len(tlv_bytes) * 8
                                header_descriptor.fields.append(
                                    FieldDescriptor(id=tlv_field_map[tlv_type],     position=0, value=Buffer(tlv_bytes, tlv_bit_length))
                                )
                                offset                   += tlv_bit_length
                        # Add the MIC at the end
                        header_descriptor.fields.append(
                            FieldDescriptor(id=ThreadMLEFields.MIC,                 position=0, value=Buffer(mic_bytes,         len(mic_bytes) * 8))
                        )
                        # Update header length
                        for field in header_descriptor.fields:
                            header_descriptor.length += field.value.length
                                                                
                    elif message.type == COAP:
                        coap_version    = (message.coap.version & 0x03).to_bytes(1, 'big')
                        coap_type       = (message.coap.type & 0x03).to_bytes(1, 'big')
                        token_length    = (len(message.coap.token) & 0x0F).to_bytes(1, 'big')
                        coap_code       = message.coap.code.to_bytes()
                        message_id      = struct.pack(">H", message.coap.message_id)
                        token           = message.coap.token
                
                        header_descriptor.fields.extend([ 
                        FieldDescriptor(id=ThreadCoAPFields.VERSION,         position=0, value=Buffer(coap_version, 2)),
                        FieldDescriptor(id=ThreadCoAPFields.TYPE,            position=0, value=Buffer(coap_type,    2)),
                        FieldDescriptor(id=ThreadCoAPFields.TOKEN_LENGTH,    position=0, value=Buffer(token_length, 4)),
                        FieldDescriptor(id=ThreadCoAPFields.CODE,            position=0, value=Buffer(coap_code,    8)),
                        FieldDescriptor(id=ThreadCoAPFields.MESSAGE_ID,      position=0, value=Buffer(message_id,   16)),
                        ])

                        # Token field
                        len_token = int(token_length.hex())
                        if len_token > 0:
                            header_descriptor.fields.append(
                                FieldDescriptor(id=ThreadCoAPFields.TOKEN,   position=0, value=Buffer(token, len_token * 8))
                                )
                            
                        # Options field
                        if len(message.coap.options) > 0:
                            last_option_number = 0

                            for option in message.coap.options:
                                # Calculate the delta based on the last option number
                                delta = option.type - last_option_number

                                serialized_delta = delta.to_bytes(1, 'big')
                                serialized_length = len(option.value).to_bytes(1, 'big')
                                serialized_value = option.value

                                header_descriptor.fields.append(
                                    FieldDescriptor(id=ThreadCoAPFields.OPTION_DELTA,   position=0, value=Buffer(serialized_delta, 4))
                                )
                                header_descriptor.fields.append(
                                    FieldDescriptor(id=ThreadCoAPFields.OPTION_LENGTH,  position=0, value=Buffer(serialized_length, 4))
                                )
                                header_descriptor.fields.append(
                                    FieldDescriptor(id=ThreadCoAPFields.OPTION_VALUE,   position=0, value=Buffer(serialized_value, len(serialized_value) * 8))
                                )
                                last_option_number = option.type

                            if message.coap.payload:
                                payload_marker = b'\xff'
                                header_descriptor.fields.append(
                                    FieldDescriptor(id=ThreadCoAPFields.PAYLOAD_MARKER, position=0, value=Buffer(payload_marker, 8))
                                )           
                    else:
                        print(f"Skipping non MLE or CoAP packet.")
                else:
                    print(f"Skipping non UDP packet.")
            else:
                print(f"Skipping non MAC DATA packet.")
        else : 
            print(f"Skipping packet : does not have a MAC header.")
        return header_descriptor