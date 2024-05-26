from __future__ import annotations
from abc import abstractmethod
from typing import Optional, Tuple
import enum
import struct

from .defs import (
    UslpVersionMissmatch,
    UslpTypeMissmatch,
    UslpInvalidRawPacketOrFrameLen,
)

USLP_VERSION_NUMBER = 0b1100


class HeaderType(enum.Enum):
    NON_TRUNCATED = 0
    TRUNCATED = 1


class SourceOrDestField(enum.IntEnum):
    SOURCE = 0
    DEST = 1


class BypassSequenceControlFlag(enum.IntEnum):
    SEQ_CTRLD_QOS = 0
    EXPEDITED_QOS = 1


class ProtocolCommandFlag(enum.IntEnum):
    USER_DATA = 0
    PROTOCOL_INFORMATION = 1


class PrimaryHeaderBase:
    def __init__(
        self,
        scid: int,
        src_dest: SourceOrDestField,
        vcid: int,
        map_id: int,
    ):
        self.scid = scid
        self.src_dest = src_dest
        self.vcid = vcid
        self.map_id = map_id

    def _pack_common_header(self, truncated: bool = False) -> bytearray:
        packet = bytearray()
        if (
            (self.scid > pow(2, 16) - 1)
            or (self.vcid > pow(2, 6) - 1)
            or (self.map_id > pow(2, 4) - 1)
        ):
            raise ValueError
        packet.append((USLP_VERSION_NUMBER << 4) | (self.scid >> 12) & 0b1111)
        packet.append((self.scid >> 4) & 0xFF)
        packet.append(
            ((self.scid & 0b1111) << 4)
            | (self.src_dest << 3)
            | (self.vcid >> 3) & 0b111
        )
        packet.append((self.vcid & 0b111) << 5 | (self.map_id << 1) | truncated)
        return packet

    @abstractmethod
    def len(self) -> int:
        return 0

    @abstractmethod
    def truncated(self) -> bool:
        return False

    @staticmethod
    def _unpack_raw_header_base_fields(
        raw_packet: bytes,
        truncated: bool = False,
        uslp_version: int = USLP_VERSION_NUMBER,
    ) -> Tuple[int, SourceOrDestField, int, int]:
        if len(raw_packet) < 4:
            raise UslpInvalidRawPacketOrFrameLen
        version_number = (raw_packet[0] & 0xF0) >> 4
        if version_number != uslp_version:
            raise UslpVersionMissmatch
        scid = (
            (raw_packet[0] & 0x0F) << 12
            | (raw_packet[1] << 4)
            | ((raw_packet[2] & 0xF0) >> 4)
        )
        src_dest = SourceOrDestField((raw_packet[2] & 0x08) >> 3)
        vcid = ((raw_packet[2] & 0b111) << 3) | ((raw_packet[3] >> 5) & 0b111)
        map_id = (raw_packet[3] >> 1) & 0b1111
        end_of_frame_primary_header = raw_packet[3] & 0b1
        if end_of_frame_primary_header != truncated:
            raise UslpTypeMissmatch
        return scid, src_dest, vcid, map_id


class TruncatedPrimaryHeader(PrimaryHeaderBase):
    """Trucated USLP transfer frame primary header with a length of 4 bytes. For more information,
    refer to the USLP Blue Book CCSDS 732.1-B-2.
    p.163

    Only contains a subset of the regular primary header
    1. Transfer Frame Version Number or TFVN (4 bits)
    2. Spacecraft ID or SCID (16 bits)
    3. Source or destination identifier (1 bit)
    4. Virtual Channel ID or VCID (6 bits)
    5. Multiplexer Access Point or MAP ID (4 bits)
    6. End of Frame Primary Header (1 bit)
    """

    def __init__(
        self,
        scid: int,
        src_dest: SourceOrDestField,
        vcid: int,
        map_id: int,
    ):
        super().__init__(scid=scid, src_dest=src_dest, vcid=vcid, map_id=map_id)

    def pack(self) -> bytearray:
        return self._pack_common_header(truncated=True)

    @classmethod
    def __empty(cls) -> TruncatedPrimaryHeader:
        return TruncatedPrimaryHeader(
            scid=0x00, src_dest=SourceOrDestField.DEST, vcid=0x00, map_id=0x00
        )

    def len(self):
        return 4

    def truncated(self) -> bool:
        return True

    @classmethod
    def unpack(
        cls,
        raw_packet: bytes,
        uslp_version: int = USLP_VERSION_NUMBER,
    ) -> TruncatedPrimaryHeader:
        """Unpack USLP primary header from raw bytearray.

        :param raw_packet:
        :param uslp_version: Expected USLP version, 0b1100 by default
        :raises ValueError: Wrong packet length
        :raises UslpVersionMissmatch: Detected USLP version is not 0b1100
        :raises UslpTypeMissmatch: End of Frame Primary Header was 0,
            should be 1 for truncated packets
        :return:
        """
        packet = cls.__empty()
        raw_unpacked_tuple = cls._unpack_raw_header_base_fields(
            raw_packet=raw_packet,
            truncated=True,
            uslp_version=uslp_version,
        )
        packet.scid = raw_unpacked_tuple[0]
        packet.src_dest = raw_unpacked_tuple[1]
        packet.vcid = raw_unpacked_tuple[2]
        packet.map_id = raw_unpacked_tuple[3]
        return packet


class PrimaryHeader(PrimaryHeaderBase):
    """USLP transfer frame primary header with a length of 4 to 14 bytes. It consists of 13
    fields positioned contiguously. For more information, refer to the USLP Blue Book
    CCSDS 732.1-B-2 p.77

    1. Transfer Frame Version Number or TFVN (4 bits)
    2. Spacecraft ID or SCID (16 bits)
    3. Source or destination identifier (1 bit)
    4. Virtual Channel ID or VCID (6 bits)
    5. Multiplexer Access Point or MAP ID (4 bits)
    6. End of Frame Primary Header (1 bit)
    7. Frame Length (16 bits)
    8. Bypass/Sequence Control Flag (1 bit)
    9. Protocol Control Command Flag (1 bit)
    10. Reserve Spares (2 bits)
    11. OCF flag (1 bit)
    12. VCF count length (3 bits)
    13. VCF count (0 to 56 bits)
    """

    def __init__(
        self,
        scid: int,
        src_dest: SourceOrDestField,
        vcid: int,
        map_id: int,
        frame_len: int,
        bypass_seq_ctrl_flag: BypassSequenceControlFlag,
        prot_ctrl_cmd_flag: ProtocolCommandFlag,
        op_ctrl_flag: bool,
        vcf_count_len: int = 0,
        vcf_count: Optional[int] = None,
    ):
        super().__init__(scid, src_dest, vcid, map_id)
        self.frame_len = frame_len
        self.bypass_seq_ctrl_flag = bypass_seq_ctrl_flag
        self.prot_ctrl_cmd_flag = prot_ctrl_cmd_flag
        self.op_ctrl_flag = op_ctrl_flag
        self.vcf_count_len = vcf_count_len
        self.vcf_count = vcf_count

    def pack(self) -> bytearray:
        packet = self._pack_common_header()
        packet.append((self.frame_len >> 8) & 0xFF)
        packet.append(self.frame_len & 0xFF)
        packet.append(
            (self.bypass_seq_ctrl_flag << 7)
            | (self.prot_ctrl_cmd_flag << 6)
            | (self.op_ctrl_flag << 3)
            | self.vcf_count_len
        )
        if self.vcf_count_len > 0 and self.vcf_count is None:
            raise ValueError
        if self.vcf_count_len == 1:
            packet.append(self.vcf_count)
        elif self.vcf_count_len == 2:
            packet.extend(struct.pack("!H", self.vcf_count))
        elif self.vcf_count_len == 4:
            packet.extend(struct.pack("!I", self.vcf_count))
        else:
            for idx in range(self.vcf_count_len, 0, -1):
                packet.append((self.vcf_count >> ((idx - 1) * 8)) & 0xFF)
        return packet

    def truncated(self) -> bool:
        return False

    @classmethod
    def __empty(cls) -> PrimaryHeader:
        return PrimaryHeader(
            scid=0,
            src_dest=SourceOrDestField.SOURCE,
            map_id=0,
            vcid=0,
            frame_len=0,
            vcf_count=0,
            op_ctrl_flag=False,
            vcf_count_len=0,
            prot_ctrl_cmd_flag=ProtocolCommandFlag.USER_DATA,
            bypass_seq_ctrl_flag=BypassSequenceControlFlag.SEQ_CTRLD_QOS,
        )

    @classmethod
    def unpack(
        cls, raw_packet: bytes, uslp_version: int = USLP_VERSION_NUMBER
    ) -> PrimaryHeader:
        """Unpack a regular transfer frame header from a raw bytearray

        :param raw_packet:
        :param uslp_version:
        :raises ValueError: Given bytearray too short
        :return:
        """
        packet = cls.__empty()
        if len(raw_packet) < 7:
            raise UslpInvalidRawPacketOrFrameLen
        raw_unpacked_tuple = cls._unpack_raw_header_base_fields(
            raw_packet=raw_packet,
            truncated=False,
            uslp_version=uslp_version,
        )
        packet.scid = raw_unpacked_tuple[0]
        packet.src_dest = raw_unpacked_tuple[1]
        packet.vcid = raw_unpacked_tuple[2]
        packet.map_id = raw_unpacked_tuple[3]
        packet.frame_len = raw_packet[4] << 8 | raw_packet[5]
        packet.bypass_seq_ctrl_flag = (raw_packet[6] >> 7) & 0x01
        packet.prot_ctrl_cmd_flag = (raw_packet[6] >> 6) & 0x01
        packet.op_ctrl_flag = (raw_packet[6] >> 3) & 0x01
        packet.vcf_count_len = raw_packet[6] & 0b111
        if packet.vcf_count_len > len(raw_packet) - 7:
            raise UslpInvalidRawPacketOrFrameLen
        if packet.vcf_count_len == 1:
            packet.vcf_count = raw_packet[7]
        elif packet.vcf_count_len == 2:
            packet.vcf_count = struct.unpack("!H", raw_packet[7:9])[0]
        elif packet.vcf_count_len == 4:
            packet.vcf_count = struct.unpack("!I", raw_packet[7:11])[0]
        else:
            packet.vcf_count = 0
            end = packet.vcf_count_len
            for idx in range(0, packet.vcf_count_len):
                packet.vcf_count |= raw_packet[7 + idx] << ((end - 1) * 8)
                end -= 1
        return packet

    def len(self):
        return 7 + self.vcf_count_len


def determine_header_type(header_start: bytes) -> HeaderType:
    """Determine header type from raw header.
    :param header_start:
    :raises ValueError: Passed bytearray shorter than minimum length 4
    :return:
    """
    if len(header_start) < 4:
        raise ValueError
    if header_start[3] & 0x01:
        return HeaderType.TRUNCATED
    else:
        return HeaderType.NON_TRUNCATED
