#!/usr/bin/env python3
from typing import Optional
from unittest import TestCase

from spacepackets.ccsds.spacepacket import (
    PacketId,
    PacketTypes,
    PacketSeqCtrl,
    SequenceFlags,
    SpacePacketHeader,
)
from spacepackets.ecss import PacketFieldEnum
from spacepackets.ecss.tc import PusTelecommand
from spacepackets.ecss.conf import set_default_tm_apid
from spacepackets.util import PrintFormats
from spacepackets.ecss.tm import (
    PusTelemetry,
    CdsShortTimestamp,
    PusVersion,
    PusTmSecondaryHeader,
)
from spacepackets.ecss.pus_17_test import Service17Tm
from spacepackets.ecss.pus_1_verification import (
    Service1Tm,
    RequestId,
    Subservices,
    VerificationParams,
    UnpackParams,
    FailureNotice,
    create_acceptance_success_tm,
    create_acceptance_failure_tm,
    create_start_success_tm,
    create_step_success_tm,
    create_completion_success_tm,
    create_start_failure_tm,
    create_step_failure_tm,
    create_completion_failure_tm,
    StepId,
    ErrorCode,
)


class TestTelemetry(TestCase):
    def setUp(self) -> None:
        self.ping_reply = PusTelemetry(
            service=17,
            subservice=2,
            apid=0xEF,
            seq_count=22,
            source_data=bytearray(),
            time=CdsShortTimestamp.init_from_current_time(),
        )
        self.ping_reply_raw = self.ping_reply.pack()

    def test_state(self):
        self.assertEqual(
            self.ping_reply.get_source_data_string(PrintFormats.HEX), "hex []"
        )
        self.assertEqual(
            self.ping_reply.get_source_data_string(PrintFormats.DEC), "dec []"
        )
        self.assertEqual(
            self.ping_reply.get_source_data_string(PrintFormats.BIN), "bin []"
        )
        self.assertEqual(self.ping_reply.subservice, 2)
        self.assertEqual(self.ping_reply.service, 17)
        self.assertEqual(self.ping_reply.seq_count, 22)
        self.assertEqual(self.ping_reply.sp_header.data_len, 15)
        self.assertEqual(self.ping_reply.packet_len, 22)

    def test_state_setting(self):
        self.ping_reply.sp_header.apid = 0x22
        source_data = bytearray([0x42, 0x38])
        self.ping_reply.tm_data = source_data
        self.assertEqual(self.ping_reply.apid, 0x22)
        self.assertEqual(
            self.ping_reply.pus_tm_sec_header.pus_version, PusVersion.PUS_C
        )
        self.assertTrue(self.ping_reply.valid)
        self.assertEqual(self.ping_reply.tm_data, source_data)
        self.assertEqual(self.ping_reply.packet_id.raw(), 0x0822)
        self.assertEqual(self.ping_reply.packet_len, 24)

    def test_service_from_raw(self):
        self.assertEqual(
            PusTelemetry.service_from_bytes(raw_bytearray=self.ping_reply_raw), 17
        )

    def test_service_from_raw_invalid(self):
        self.assertRaises(ValueError, PusTelemetry.service_from_bytes, bytearray())

    def test_source_data_string_getters(self):
        set_default_tm_apid(0x22)
        source_data = bytearray([0x42, 0x38])
        self.ping_reply.tm_data = source_data
        self.assertEqual(
            self.ping_reply.get_source_data_string(PrintFormats.HEX), "hex [42,38]"
        )
        self.assertEqual(
            self.ping_reply.get_source_data_string(PrintFormats.DEC), "dec [66,56]"
        )
        self.assertEqual(
            self.ping_reply.get_source_data_string(PrintFormats.BIN),
            "bin [\n0:01000010\n1:00111000\n]",
        )

    def test_print(self):
        self.ping_reply.print_full_packet_string(PrintFormats.HEX)

    def test_sec_header(self):
        raw_secondary_packet_header = self.ping_reply.pus_tm_sec_header.pack()
        self.assertEqual(raw_secondary_packet_header[0], 0x20)
        # Service
        self.assertEqual(raw_secondary_packet_header[1], 17)
        # Subservice
        self.assertEqual(raw_secondary_packet_header[2], 2)

    def test_full_printout(self):
        crc16 = self.ping_reply.crc16
        crc_string = f"{(crc16 & 0xff00) >> 8:02x},{crc16 & 0xff:02x}"
        raw_time = self.ping_reply.pus_tm_sec_header.time.pack()
        raw_space_packet_header = self.ping_reply.sp_header.pack()
        sp_header_as_str = raw_space_packet_header.hex(sep=",", bytes_per_sep=1)
        raw_secondary_packet_header = self.ping_reply.pus_tm_sec_header.pack()
        second_header_as_str = raw_secondary_packet_header.hex(sep=",", bytes_per_sep=1)
        expected_printout = f"hex [{sp_header_as_str},{second_header_as_str},"
        expected_printout += f"{crc_string}]"
        self.assertEqual(
            self.ping_reply.get_full_packet_string(PrintFormats.HEX), expected_printout
        )

    def test_print_2(self):
        print(self.ping_reply)
        print(self.ping_reply.__repr__())

    def test_unpack(self):
        source_data = bytearray([0x42, 0x38])
        self.ping_reply.tm_data = source_data
        self.ping_reply.sp_header.apid = 0x22
        self.ping_reply_raw = self.ping_reply.pack()
        pus_17_tm_unpacked = PusTelemetry.unpack(raw_telemetry=self.ping_reply_raw)

        self.assertEqual(pus_17_tm_unpacked.apid, 0x22)
        self.assertEqual(
            pus_17_tm_unpacked.pus_tm_sec_header.pus_version, PusVersion.PUS_C
        )
        self.assertTrue(pus_17_tm_unpacked.valid)
        self.assertEqual(pus_17_tm_unpacked.tm_data, source_data)
        self.assertEqual(pus_17_tm_unpacked.packet_id.raw(), 0x0822)

        correct_size = self.ping_reply_raw[4] << 8 | self.ping_reply_raw[5]
        # Set length field invalid
        self.ping_reply_raw[4] = 0x00
        self.ping_reply_raw[5] = 0x00
        self.assertRaises(ValueError, PusTelemetry.unpack, self.ping_reply_raw)
        self.ping_reply_raw[4] = 0xFF
        self.ping_reply_raw[5] = 0xFF
        self.assertRaises(ValueError, PusTelemetry.unpack, self.ping_reply_raw)

        self.ping_reply_raw[4] = (correct_size & 0xFF00) >> 8
        self.ping_reply_raw[5] = correct_size & 0xFF
        self.ping_reply_raw.append(0)
        # Should work with a warning
        pus_17_tm_unpacked = PusTelemetry.unpack(raw_telemetry=self.ping_reply_raw)

        # This should cause the CRC calculation to fail
        incorrect_size = correct_size + 1
        self.ping_reply_raw[4] = (incorrect_size & 0xFF00) >> 8
        self.ping_reply_raw[5] = incorrect_size & 0xFF
        pus_17_tm_unpacked = PusTelemetry.unpack(raw_telemetry=self.ping_reply_raw)

    def test_faulty_unpack(self):
        self.assertRaises(ValueError, PusTelemetry.unpack, None)
        self.assertRaises(ValueError, PusTelemetry.unpack, bytearray())

    def test_invalid_sec_header_unpack(self):
        invalid_secondary_header = bytearray([0x20, 0x00, 0x01, 0x06])
        self.assertRaises(
            ValueError, PusTmSecondaryHeader.unpack, invalid_secondary_header
        )

    def test_space_packet_conversion(self):
        ccsds_packet = self.ping_reply.to_space_packet()
        self.assertEqual(ccsds_packet.apid, self.ping_reply.apid)
        self.assertEqual(ccsds_packet.pack(), self.ping_reply.pack())
        self.assertEqual(ccsds_packet.seq_count, self.ping_reply.seq_count)
        self.assertEqual(ccsds_packet.sec_header_flag, True)
        pus_17_from_composite_fields = PusTelemetry.from_composite_fields(
            sp_header=self.ping_reply.sp_header,
            sec_header=self.ping_reply.pus_tm_sec_header,
            tm_data=self.ping_reply.tm_data,
        )
        self.assertEqual(pus_17_from_composite_fields.pack(), self.ping_reply.pack())

    def test_faulty_sec_header(self):
        with self.assertRaises(ValueError):
            # Message Counter too large
            PusTmSecondaryHeader(
                service=0,
                subservice=0,
                time=CdsShortTimestamp.init_from_current_time(),
                message_counter=129302,
            )

    def test_invalid_raw_size(self):
        # Set length field invalid
        self.ping_reply_raw[4] = 0x00
        self.ping_reply_raw[5] = 0x00
        self.assertRaises(ValueError, PusTelemetry.unpack, self.ping_reply_raw)

    def test_service_17_tm(self):
        srv_17_tm = Service17Tm(subservice=2)
        self.assertEqual(srv_17_tm.pus_tm.subservice, 2)
        srv_17_tm_raw = srv_17_tm.pack()
        srv_17_tm_unpacked = Service17Tm.unpack(
            raw_telemetry=srv_17_tm_raw, pus_version=PusVersion.PUS_C
        )
        self.assertEqual(srv_17_tm_unpacked.pus_tm.subservice, 2)

    def test_req_id(self):
        tc_packet_id = PacketId(ptype=PacketTypes.TC, sec_header_flag=True, apid=0x42)
        tc_psc = PacketSeqCtrl(seq_flags=SequenceFlags.UNSEGMENTED, seq_count=22)
        req_id = RequestId(tc_packet_id, tc_psc)
        print(req_id)
        req_id_as_bytes = req_id.pack()
        unpack_req_id = RequestId.unpack(req_id_as_bytes)
        self.assertEqual(unpack_req_id.tc_packet_id.raw(), tc_packet_id.raw())
        self.assertEqual(unpack_req_id.tc_psc.raw(), tc_psc.raw())
        sp_header = SpacePacketHeader.from_composite_fields(
            packet_id=tc_packet_id, psc=tc_psc, data_length=12
        )
        unpack_req_id = RequestId.from_sp_header(sp_header)
        self.assertEqual(unpack_req_id.tc_packet_id.raw(), tc_packet_id.raw())
        self.assertEqual(unpack_req_id.tc_psc.raw(), tc_psc.raw())
        with self.assertRaises(ValueError):
            RequestId.unpack(bytes([0, 1, 2]))

    def test_failure_notice(self):
        error_code = PacketFieldEnum(pfc=8, val=2)
        failure_notice = FailureNotice(code=error_code, data=bytes([0, 2, 4, 8]))
        self.assertEqual(failure_notice.code.val, error_code.val)
        self.assertEqual(failure_notice.code.pfc, error_code.pfc)
        notice_raw = failure_notice.pack()
        notice_unpacked = FailureNotice.unpack(notice_raw, 1, 4)
        self.assertEqual(notice_unpacked.code.val, error_code.val)
        self.assertEqual(notice_unpacked.code.pfc, error_code.pfc)
        self.assertEqual(notice_unpacked.data, bytes([0, 2, 4, 8]))

    def test_service_1_tm_acc_success(self):
        self._generic_test_srv_1_success(Subservices.TM_ACCEPTANCE_SUCCESS)

    def test_service_1_tm_start_success(self):
        self._generic_test_srv_1_success(Subservices.TM_START_SUCCESS)

    def test_service_1_tm_step_success(self):
        self._generic_test_srv_1_success(Subservices.TM_STEP_SUCCESS)

    def test_service_1_tm_completion_success(self):
        self._generic_test_srv_1_success(Subservices.TM_COMPLETION_SUCCESS)

    def _generic_test_srv_1_success(self, subservice: Subservices):
        pus_tc = PusTelecommand(service=17, subservice=1)
        helper_created = None
        step_id = None
        if subservice == Subservices.TM_ACCEPTANCE_SUCCESS:
            helper_created = create_acceptance_success_tm(pus_tc)
        elif subservice == Subservices.TM_START_SUCCESS:
            helper_created = create_start_success_tm(pus_tc)
        elif subservice == Subservices.TM_STEP_SUCCESS:
            step_id = PacketFieldEnum.with_byte_size(1, 4)
            helper_created = create_step_success_tm(pus_tc, step_id)
        elif subservice == Subservices.TM_COMPLETION_SUCCESS:
            helper_created = create_completion_success_tm(pus_tc)
        self._test_srv_1_success_tm(
            pus_tc,
            Service1Tm(
                subservice=subservice,
                verif_params=VerificationParams(
                    req_id=RequestId(pus_tc.packet_id, pus_tc.packet_seq_ctrl),
                    step_id=step_id,
                ),
            ),
            subservice,
        )
        if helper_created is not None:
            self._test_srv_1_success_tm(pus_tc, helper_created, subservice, step_id)

    def test_verif_params(self):
        sp_header = SpacePacketHeader(
            packet_type=PacketTypes.TM,
            apid=0x22,
            sec_header_flag=False,
            seq_count=22,
            data_len=35,
        )
        verif_param = VerificationParams(req_id=RequestId.from_sp_header(sp_header))
        self.assertEqual(verif_param.len(), 4)
        verif_param.step_id = StepId(pfc=8, val=12)
        self.assertEqual(verif_param.len(), 5)
        verif_param.step_id.pfc = 16
        self.assertEqual(verif_param.len(), 6)
        verif_param.failure_notice = FailureNotice(
            code=ErrorCode(pfc=16, val=22), data=bytes([0, 1, 2])
        )
        self.assertEqual(verif_param.len(), 11)

    def test_service_1_tm_acceptance_failure(self):
        self._generic_test_srv_1_failure(Subservices.TM_ACCEPTANCE_FAILURE)

    def test_service_1_tm_start_failure(self):
        self._generic_test_srv_1_failure(Subservices.TM_START_FAILURE)

    def test_service_1_tm_step_failure(self):
        self._generic_test_srv_1_failure(Subservices.TM_STEP_FAILURE)

    def test_service_1_tm_completion_failure(self):
        self._generic_test_srv_1_failure(Subservices.TM_COMPLETION_FAILURE)

    def _test_srv_1_success_tm(
        self,
        pus_tc: PusTelecommand,
        srv_1_tm: Service1Tm,
        subservice: Subservices,
        step_id: Optional[PacketFieldEnum] = None,
    ):
        self.assertEqual(srv_1_tm.pus_tm.subservice, subservice)
        self.assertEqual(srv_1_tm.tc_req_id.tc_packet_id, pus_tc.packet_id)
        self.assertEqual(srv_1_tm.tc_req_id.tc_psc, pus_tc.packet_seq_ctrl)
        srv_1_tm_raw = srv_1_tm.pack()
        srv_1_tm_unpacked = Service1Tm.unpack(srv_1_tm_raw, UnpackParams())
        self.assertEqual(
            srv_1_tm_unpacked.tc_req_id.tc_packet_id.raw(), pus_tc.packet_id.raw()
        )
        self.assertEqual(
            srv_1_tm_unpacked.tc_req_id.tc_psc.raw(), pus_tc.packet_seq_ctrl.raw()
        )
        if step_id is not None and subservice == Subservices.TM_STEP_SUCCESS:
            self.assertEqual(srv_1_tm_unpacked.step_id, step_id)

    def _generic_test_srv_1_failure(self, subservice: Subservices):
        pus_tc = PusTelecommand(service=17, subservice=1)
        failure_notice = FailureNotice(
            code=PacketFieldEnum.with_byte_size(1, 8), data=bytes([2, 4])
        )
        helper_created = None
        step_id = None
        if subservice == Subservices.TM_ACCEPTANCE_FAILURE:
            helper_created = create_acceptance_failure_tm(pus_tc, failure_notice)
        elif subservice == Subservices.TM_START_FAILURE:
            helper_created = create_start_failure_tm(pus_tc, failure_notice)
        elif subservice == Subservices.TM_STEP_FAILURE:
            step_id = PacketFieldEnum.with_byte_size(2, 12)
            helper_created = create_step_failure_tm(
                pus_tc, failure_notice=failure_notice, step_id=step_id
            )
        elif subservice == Subservices.TM_COMPLETION_FAILURE:
            helper_created = create_completion_failure_tm(pus_tc, failure_notice)
        self._test_srv_1_failure_comparison_helper(
            pus_tc,
            Service1Tm(
                subservice=subservice,
                verif_params=VerificationParams(
                    req_id=RequestId(pus_tc.packet_id, pus_tc.packet_seq_ctrl),
                    failure_notice=failure_notice,
                    step_id=step_id,
                ),
            ),
            subservice=subservice,
            failure_notice=failure_notice,
            step_id=step_id,
        )
        if helper_created is not None:
            self._test_srv_1_failure_comparison_helper(
                pus_tc=pus_tc,
                srv_1_tm=helper_created,
                failure_notice=failure_notice,
                subservice=subservice,
                step_id=step_id,
            )

    def _test_srv_1_failure_comparison_helper(
        self,
        pus_tc: PusTelecommand,
        srv_1_tm: Service1Tm,
        subservice: Subservices,
        failure_notice: Optional[FailureNotice],
        step_id: Optional[PacketFieldEnum] = None,
    ):
        self.assertEqual(srv_1_tm.pus_tm.subservice, subservice)
        self.assertEqual(srv_1_tm.tc_req_id.tc_packet_id, pus_tc.packet_id)
        self.assertEqual(srv_1_tm.tc_req_id.tc_psc, pus_tc.packet_seq_ctrl)
        srv_1_tm_raw = srv_1_tm.pack()
        unpack_params = UnpackParams()
        if failure_notice is not None:
            unpack_params.bytes_err_code = failure_notice.code.len()
        if step_id is not None:
            unpack_params.bytes_step_id = step_id.len()
        srv_1_tm_unpacked = Service1Tm.unpack(srv_1_tm_raw, unpack_params)
        self.assertEqual(srv_1_tm_unpacked.error_code.val, failure_notice.code.val)
        self.assertEqual(
            srv_1_tm_unpacked.tc_req_id.tc_packet_id.raw(), pus_tc.packet_id.raw()
        )
        self.assertEqual(
            srv_1_tm_unpacked.tc_req_id.tc_psc.raw(), pus_tc.packet_seq_ctrl.raw()
        )
        if failure_notice is not None:
            self.assertEqual(
                srv_1_tm_unpacked.failure_notice.pack(), failure_notice.pack()
            )
        if step_id is not None:
            self.assertEqual(srv_1_tm_unpacked.step_id.pack(), step_id.pack())