from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from spacepackets.crc import CRC16_CCITT_FUNC
from spacepackets.exceptions import BytesTooShortError, InvalidCrcCcitt16


@dataclass
class MasterChannelId:
    transfer_frame_version: int
    spacecraft_id: int


@dataclass
class TransferFrameDataFieldStatus:
    secondary_header_flag: bool
    sync_flag: bool
    packet_order_flag: bool
    segment_len_id: int
    first_header_pointer: int

    @classmethod
    def unpack(cls, data: bytes) -> TransferFrameDataFieldStatus:
        if len(data) < 2:
            raise BytesTooShortError(2, len(data))
        return cls(
            bool((data[0] >> 7) & 0b1),
            bool((data[0] >> 6) & 0b1),
            bool((data[0] >> 5) & 0b1),
            (data[0] >> 4) & 0b11,
            ((data[0] >> 3 & 0b111) << 8) | data[1],
        )


class TmFramePrimaryHeader:
    def __init__(
        self,
        master_channel_id: MasterChannelId,
        vc_id: int,
        ocf_flag: bool,
        master_ch_frame_count: int,
        vc_frame_count: int,
        frame_datafield_status: TransferFrameDataFieldStatus,
    ):
        self.master_channel_id = master_channel_id
        self.vc_id = vc_id
        self.ocf_flag = ocf_flag
        self.master_ch_frame_count = master_ch_frame_count
        self.vc_frame_count = vc_frame_count
        self.frame_datafield_status = frame_datafield_status

    @classmethod
    def unpack(cls, data: bytes) -> TmFramePrimaryHeader:
        tf_version = (data[0] >> 6) & 0b11
        spacecraft_id = (data[0] & 0b111111 << 8) | ((data[1] >> 4) & 0b1111)
        master_channel_id = MasterChannelId(tf_version, spacecraft_id)
        vc_id = (data[1] >> 1) & 0b111
        ocf_flag = bool(data[1] & 0b1)
        master_ch_frame_count = data[2]
        vc_frame_count = data[3]
        frame_datafield_status = TransferFrameDataFieldStatus.unpack(data[4:])
        return cls(
            master_channel_id,
            vc_id,
            ocf_flag,
            master_ch_frame_count,
            vc_frame_count,
            frame_datafield_status,
        )


@dataclass
class TransferFrameSecondaryHeader:
    version_number: int
    secondary_header_len: int
    data_field: bytes

    @classmethod
    def unpack(cls, data: bytes) -> TransferFrameSecondaryHeader:
        if len(data) < 1:
            raise BytesTooShortError(1, len(data))
        secondary_header_len = data[0] & 0b111111
        return cls(
            version_number=(data[0] >> 6) & 0b11,
            secondary_header_len=secondary_header_len,
            data_field=data[1 : 1 + secondary_header_len],
        )


class TmTransferFrame:
    def __init__(
        self,
        primary_header: TmFramePrimaryHeader,
        secondary_header: Optional[TransferFrameSecondaryHeader],
        data_field: bytes,
        op_ctrl_field: Optional[bytes],
        frame_error_control: Optional[bytes],
    ) -> None:
        self.primary_header = primary_header
        self.secondary_header = secondary_header
        self.data_field = data_field
        self.op_ctrl_field = op_ctrl_field
        self.frame_error_control = frame_error_control

    @classmethod
    def unpack(cls, raw_frame: bytes, has_error_control_field: bool) -> TmTransferFrame:
        primary_header = TmFramePrimaryHeader.unpack(raw_frame)
        secondary_header = None
        current_idx = 6
        if primary_header.frame_datafield_status.secondary_header_flag:
            secondary_header = TransferFrameSecondaryHeader.unpack(
                raw_frame[current_idx:]
            )
            current_idx += secondary_header.secondary_header_len
        data_end = len(raw_frame)
        op_ctrl_field = None
        frame_error_control = None
        if has_error_control_field:
            if current_idx + 2 > len(raw_frame):
                raise BytesTooShortError(current_idx + 2, len(raw_frame))
            frame_error_control = raw_frame[-2:]
            # CRC16-CCITT checksum
            if CRC16_CCITT_FUNC(raw_frame) != 0:
                raise InvalidCrcCcitt16(raw_frame)
            # Used for length checks.
            current_idx += 2
            data_end -= 2
        if primary_header.ocf_flag:
            if current_idx + 4 > len(raw_frame):
                raise BytesTooShortError(current_idx + 4, len(raw_frame))
            op_ctrl_field = raw_frame[-6:-2]
            data_end -= 4
        frame_data_field = raw_frame[current_idx:data_end]
        return cls(
            primary_header,
            secondary_header,
            frame_data_field,
            op_ctrl_field,
            frame_error_control,
        )
