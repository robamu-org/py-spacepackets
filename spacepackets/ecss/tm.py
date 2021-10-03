from __future__ import annotations

from crcmod.predefined import mkPredefinedCrcFun

from spacepackets.log import get_console_logger
from spacepackets.ccsds.spacepacket import SpacePacketHeader, SPACE_PACKET_HEADER_SIZE, \
    get_total_space_packet_len_from_len_field, PacketTypes
from spacepackets.ccsds.time import CdsShortTimestamp, read_p_field
from spacepackets.ecss.conf import get_pus_tm_version, PusVersion, get_tm_apid


def get_service_from_raw_pus_packet(raw_bytearray: bytearray) -> int:
    """Determine the service ID from a raw packet, which can be used for packet deserialization.

    It is assumed that the user already checked that the raw bytearray contains a PUS packet and
    only basic sanity checks will be performed.
    :raise ValueError: If raw bytearray is too short
    """
    if len(raw_bytearray) < 8:
        raise ValueError
    return raw_bytearray[7]


class PusTelemetry:
    """Generic PUS telemetry class representation.
    It is instantiated by passing the raw pus telemetry packet (bytearray) to the constructor.
    It automatically deserializes the packet, exposing various packet fields via getter functions.
    PUS Telemetry structure according to ECSS-E-70-41A p.46. Also see structure below (bottom).
    """
    CDS_SHORT_SIZE = 7
    PUS_TIMESTAMP_SIZE = CDS_SHORT_SIZE

    def __init__(
            self, service_id: int, subservice_id: int, time: CdsShortTimestamp = None, ssc: int = 0,
            source_data: bytearray = bytearray([]), apid: int = -1, message_counter: int = 0,
            space_time_ref: int = 0b0000, destination_id: int = 0,
            packet_version: int = 0b000, pus_version: PusVersion = PusVersion.GLOBAL_CONFIG,
            pus_tm_version: int = 0b0001, ack: int = 0b1111, secondary_header_flag: bool = True,
    ):
        if apid == -1:
            apid = get_tm_apid()
        if pus_version == PusVersion.GLOBAL_CONFIG:
            pus_version = get_pus_tm_version()
        if time is None:
            time = CdsShortTimestamp.init_from_current_time()
        # packet type for telemetry is 0 as specified in standard
        # specified in standard
        packet_type = PacketTypes.PACKET_TYPE_TM
        self._source_data = source_data
        data_length = self.get_source_data_length(
            timestamp_len=PusTelemetry.PUS_TIMESTAMP_SIZE, pus_version=pus_version
        )
        self.space_packet_header = SpacePacketHeader(
            apid=apid, packet_type=packet_type, secondary_header_flag=secondary_header_flag,
            packet_version=packet_version, data_length=data_length, source_sequence_count=ssc
        )
        self.secondary_packet_header = PusTmSecondaryHeader(
            pus_version=pus_version, service_id=service_id, subservice_id=subservice_id,
            message_counter=message_counter, destination_id=destination_id,
            spacecraft_time_ref=space_time_ref, time=time
        )
        self._valid = False
        self._crc16 = 0
        self.print_info = ''

    @classmethod
    def __empty(cls, pus_version: PusVersion = PusVersion.GLOBAL_CONFIG) -> PusTelemetry:
        return PusTelemetry(
            service_id=0, subservice_id=0, time=CdsShortTimestamp.init_from_current_time()
        )

    def pack(self) -> bytearray:
        """Serializes the PUS telemetry into a raw packet.
        """
        tm_packet_raw = bytearray()
        # PUS Header
        tm_packet_raw.extend(self.space_packet_header.pack())
        # PUS Source Data Field
        tm_packet_raw.extend(self.secondary_packet_header.pack())
        # Source Data
        tm_packet_raw.extend(self._source_data)
        # CRC16-CCITT checksum
        crc_func = mkPredefinedCrcFun(crc_name='crc-ccitt-false')
        self._crc16 = crc_func(tm_packet_raw)
        tm_packet_raw.append((self._crc16 & 0xff00) >> 8)
        tm_packet_raw.append(self._crc16 & 0xff)
        return tm_packet_raw

    @classmethod
    def unpack(
            cls, raw_telemetry: bytearray, pus_version: PusVersion = PusVersion.GLOBAL_CONFIG
    ) -> PusTelemetry:
        """Attempts to construct a generic PusTelemetry class given a raw bytearray.
        :param pus_version:
        :raises ValueError: if the format of the raw bytearray is invalid, for example the length
        :param raw_telemetry:
        """
        if raw_telemetry is None:
            logger = get_console_logger()
            logger.warning("Given byte stream invalid!")
            raise ValueError
        elif len(raw_telemetry) == 0:
            logger = get_console_logger()
            logger.warning("Given byte stream is empty")
            raise ValueError
        pus_tm = cls.__empty(pus_version=pus_version)
        pus_tm.space_packet_header = SpacePacketHeader.unpack(space_packet_raw=raw_telemetry)
        expected_packet_len = get_total_space_packet_len_from_len_field(
            pus_tm.space_packet_header.data_length
        )
        if expected_packet_len > len(raw_telemetry):
            logger = get_console_logger()
            logger.warning(
                f'PusTelemetry: Passed packet with length {len(raw_telemetry)} '
                f'shorter than specified packet length in PUS header {expected_packet_len}'
            )
            raise ValueError
        pus_tm.secondary_packet_header = PusTmSecondaryHeader.unpack(
            header_start=raw_telemetry[SPACE_PACKET_HEADER_SIZE:],
            pus_version=pus_version
        )
        if len(raw_telemetry) - 2 < \
                pus_tm.secondary_packet_header.get_header_size() + SPACE_PACKET_HEADER_SIZE:
            logger = get_console_logger()
            logger.warning("Passed packet too short!")
            raise ValueError
        if pus_tm.get_packet_size() != len(raw_telemetry):
            logger = get_console_logger()
            logger.warning(
                f'PusTelemetry: Packet length field '
                f'{pus_tm.space_packet_header.data_length} might be invalid!'
            )
            logger.warning(f'self.get_packet_size: {pus_tm.get_packet_size()}')
            logger.warning(f'len(raw_telemetry): {len(raw_telemetry)}')
        pus_tm._source_data = raw_telemetry[
            pus_tm.secondary_packet_header.get_header_size() + SPACE_PACKET_HEADER_SIZE:-2
        ]
        pus_tm._crc = \
            raw_telemetry[expected_packet_len - 2] << 8 | raw_telemetry[expected_packet_len - 1]
        pus_tm.print_info = ""
        pus_tm.__perform_crc_check(raw_telemetry)
        return pus_tm

    def __str__(self):
        return f"PUS TM[{self.secondary_packet_header.service_id}," \
               f"{self.secondary_packet_header.subservice_id}] with message counter " \
               f"{self.secondary_packet_header.message_counter}"

    def __repr__(self):
        return f"{self.__class__.__name__}(service={self.secondary_packet_header.service_id!r}, " \
               f"subservice={self.secondary_packet_header.subservice_id!r})"

    def get_service(self) -> int:
        """Get the service type ID
        :return: Service ID
        """
        return self.secondary_packet_header.service_id

    def get_subservice(self) -> int:
        """Get the subservice type ID
        :return: Subservice ID
        """
        return self.secondary_packet_header.subservice_id

    def is_valid(self) -> bool:
        return self._valid

    def get_tm_data(self) -> bytearray:
        """
        :return: TM application data (raw)
        """
        return self._source_data

    def get_packet_id(self) -> int:
        return self.space_packet_header.packet_id

    def __perform_crc_check(self, raw_telemetry: bytearray) -> bool:
        # CRC16-CCITT checksum
        crc_func = mkPredefinedCrcFun(crc_name='crc-ccitt-false')
        full_packet_size = self.get_packet_size()
        if len(raw_telemetry) < full_packet_size:
            logger = get_console_logger()
            logger.warning('Invalid packet length')
            return False
        data_to_check = raw_telemetry[:full_packet_size]
        crc = crc_func(data_to_check)
        if crc == 0:
            self._valid = True
            return True
        logger = get_console_logger()
        logger.warning('Invalid CRC detected !')
        return False

    def get_source_data_length(self, timestamp_len: int, pus_version: PusVersion) -> int:
        """Retrieve size of TM packet data header in bytes.
        Formula according to PUS Standard: C = (Number of octets in packet source data field) - 1.
        The size of the TM packet is the size of the packet secondary header with
        the timestamp + the length of the application data + PUS timestamp size +
        length of the CRC16 checksum - 1

        :param timestamp_len: Length of the used timestamp
        :param pus_version: Used PUS version
        :raises ValueError: Invalid PUS version
        """
        try:
            if pus_version == PusVersion.PUS_A:
                data_length = \
                    PusTmSecondaryHeader.HEADER_SIZE_WITHOUT_TIME_PUS_A + \
                    timestamp_len + len(self._source_data) + 1
            elif pus_version == PusVersion.PUS_C:
                data_length = \
                    PusTmSecondaryHeader.HEADER_SIZE_WITHOUT_TIME_PUS_C + \
                    timestamp_len + len(self._source_data) + 1
            else:
                logger = get_console_logger()
                logger.warning(f'PUS version {pus_version} not supported')
                raise ValueError
            return data_length
        except TypeError:
            print("PusTelecommand: Invalid type of application data!")
            return 0

    def specify_packet_info(self, print_info: str):
        """Caches a print information string for later printing
        :param print_info:
        :return:
        """
        self.print_info = print_info

    def append_packet_info(self, print_info: str):
        """Similar to the function above, but appends to the existing information string.
        :param print_info:
        :return:
        """
        self.print_info = self.print_info + print_info

    def get_custom_printout(self) -> str:
        """Can be used to supply any additional custom printout.
        :return: String which will be printed by TmTcPrinter class as well as logged if specified
        """
        return ""

    def get_packet_size(self) -> int:
        """Retrieve the full packet size when packed
        :return: Size of the TM packet based on the space packet header data length field.
        The space packet data field is the full length of data field minus one without
        the space packet header.
        """
        return self.space_packet_header.get_packet_size()

    def get_apid(self) -> int:
        return self.space_packet_header.apid

    def get_ssc(self) -> int:
        """Get the source sequence count
        :return: Source Sequence Count (see below, or PUS documentation)
        """
        return self.space_packet_header.ssc

    def return_full_packet_string(self) -> str:
        packet_raw = self.pack()
        return get_printable_data_string(packet_raw, len(packet_raw))

    def print_full_packet_string(self):
        """Print the full TM packet in a clean format."""
        packet_raw = self.pack()
        print(get_printable_data_string(packet_raw, len(packet_raw)))

    def print_source_data(self):
        """Prints the TM source data in a clean format
        :return:
        """
        print(get_printable_data_string(self._source_data, len(self._source_data)))

    def return_source_data_string(self) -> str:
        """Returns the source data string"""
        return get_printable_data_string(self._source_data, len(self._source_data))


class PusTmSecondaryHeader:
    """Unpacks the PUS telemetry packet secondary header.
    Currently only supports CDS short timestamps"""
    HEADER_SIZE_WITHOUT_TIME_PUS_A = 4
    HEADER_SIZE_WITHOUT_TIME_PUS_C = 7

    def __init__(
            self, pus_version: PusVersion, service_id: int, subservice_id: int,
            time: CdsShortTimestamp, message_counter: int, destination_id: int = 0,
            spacecraft_time_ref: int = 0,
    ):
        """Create a PUS telemetry secondary header object.

        :param pus_version: PUS version. ESA PUS is not supported
        :param service_id:
        :param subservice_id:
        :param time: Time field
        :param message_counter: 8 bit counter for PUS A, 16 bit counter for PUS C
        :param destination_id: Destination ID if PUS C is used
        :param spacecraft_time_ref: Space time reference if PUS C is used
        """
        self.pus_version = pus_version
        self.spacecraft_time_ref = spacecraft_time_ref
        self.pus_version = pus_version
        if self.pus_version == PusVersion.GLOBAL_CONFIG:
            self.pus_version = get_pus_tm_version()
        if self.pus_version != PusVersion.PUS_A and self.pus_version != PusVersion.PUS_C:
            raise ValueError
        self.service_id = service_id
        self.subservice_id = subservice_id
        if (self.pus_version == PusVersion.PUS_A and message_counter > 255) or \
                (self.pus_version == PusVersion.PUS_C and message_counter > 65536):
            raise ValueError
        self.message_counter = message_counter
        self.destination_id = destination_id
        self.time = time

    @classmethod
    def __empty(cls) -> PusTmSecondaryHeader:
        return PusTmSecondaryHeader(
            pus_version=PusVersion.PUS_C,
            service_id=-1,
            subservice_id=-1,
            time=CdsShortTimestamp.init_from_current_time(),
            message_counter=0
        )

    def pack(self) -> bytearray:
        secondary_header = bytearray()
        if self.pus_version == PusVersion.PUS_A:
            secondary_header.append((self.pus_version_number & 0x07) << 4)
        elif self.pus_version == PusVersion.PUS_C:
            secondary_header.append(self.pus_version << 4 | self.spacecraft_time_ref)
        secondary_header.append(self.service_id)
        secondary_header.append(self.subservice_id)
        if self.pus_version == PusVersion.PUS_A:
            secondary_header.append(self.message_counter)
        elif self.pus_version == PusVersion.PUS_C:
            secondary_header.append((self.message_counter & 0xff00) >> 8)
            secondary_header.append(self.message_counter & 0xff)
            secondary_header.append((self.destination_id & 0xff00) >> 8)
            secondary_header.append(self.destination_id & 0xff)
        secondary_header.extend(self.time.pack())
        return secondary_header

    @classmethod
    def unpack(cls, header_start: bytearray, pus_version: PusVersion) -> PusTmSecondaryHeader:
        """Unpack the PUS TM secondary header from the raw packet starting at the header index.
        The user still needs to specify the PUS version because the version field is parsed
        differently depending on the PUS version.

        :param header_start:
        :param pus_version:
        :raises ValueError: bytearray too short or PUS version missmatch.
        :return:
        """
        if pus_version == PusVersion.GLOBAL_CONFIG:
            pus_version = get_pus_tm_version()
        secondary_header = cls.__empty()
        current_idx = 0
        if pus_version == PusVersion.PUS_A:
            secondary_header.pus_version = PusVersion.PUS_A
            secondary_header.pus_version_number = (header_start[current_idx] & 0x70) >> 4
            if secondary_header.pus_version_number == 1:
                logger = get_console_logger()
                logger.warning(
                    'PUS version field value 1 found where PUS A value (0) was expected!'
                )
                raise ValueError

        elif pus_version == PusVersion.PUS_C:
            secondary_header.pus_version = PusVersion.PUS_C
            if secondary_header.pus_version != PusVersion.PUS_C:
                logger = get_console_logger()
                logger.warning(
                    f'PUS version field value {secondary_header.pus_version} found where '
                    f'PUS C value (2) was expected!'
                )
                raise ValueError
            secondary_header.pus_version_number = (header_start[current_idx] & 0xF0) >> 4
            secondary_header.spacecraft_time_ref = header_start[current_idx] & 0x0F
        if len(header_start) < secondary_header.get_header_size():
            logger = get_console_logger()
            logger.warning(
                f'Invalid PUS data field header size, '
                f'less than expected {secondary_header.get_header_size()} bytes'
            )
            raise ValueError
        current_idx += 1
        secondary_header.service_id = header_start[current_idx]
        current_idx += 1
        secondary_header.subservice_id = header_start[current_idx]
        current_idx += 1
        if pus_version == PusVersion.PUS_A:
            secondary_header.message_counter = header_start[current_idx]
            current_idx += 1
        else:
            secondary_header.message_counter = \
                header_start[current_idx] << 8 | header_start[current_idx + 1]
            current_idx += 2
        if pus_version == PusVersion.PUS_C:
            secondary_header.destination_id = \
                header_start[current_idx] << 8 | header_start[current_idx + 1]
            current_idx += 2
        # If other time formats are supported in the future, this information can be used
        #  to unpack the correct time code
        time_code_id = read_p_field(header_start[current_idx])
        if time_code_id:
            pass
        secondary_header.time = CdsShortTimestamp.unpack(
            time_field=header_start[current_idx: current_idx + PusTelemetry.PUS_TIMESTAMP_SIZE]
        )
        return secondary_header

    def get_header_size(self) -> int:
        if self.pus_version == PusVersion.PUS_A:
            return PusTelemetry.PUS_TIMESTAMP_SIZE + 4
        else:
            return PusTelemetry.PUS_TIMESTAMP_SIZE + 7


def get_printable_data_string(byte_array: bytearray, length: int) -> str:
    """Returns the TM data in a clean printable hex string format
    :return: The string
    """
    str_to_print = "["
    for index in range(length):
        str_to_print += str(hex(byte_array[index])) + " , "
    str_to_print = str_to_print.rstrip()
    str_to_print = str_to_print.rstrip(',')
    str_to_print = str_to_print.rstrip()
    str_to_print += "]"
    return str_to_print
