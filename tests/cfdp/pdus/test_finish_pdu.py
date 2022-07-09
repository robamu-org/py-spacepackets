from unittest import TestCase

from spacepackets.cfdp import (
    ConditionCode,
    EntityIdTlv,
    FileStoreResponseTlv,
    FilestoreActionCode,
    FilestoreResponseStatusCode,
    TlvTypes,
)
from spacepackets.cfdp.conf import PduConfig
from spacepackets.cfdp.pdu import FinishedPdu
from spacepackets.cfdp.pdu.finished import DeliveryCode, FileDeliveryStatus


class TestFinishPdu(TestCase):
    def test_finished_pdu(self):
        pdu_conf = PduConfig.empty()
        finish_pdu = FinishedPdu(
            delivery_code=DeliveryCode.DATA_COMPLETE,
            file_delivery_status=FileDeliveryStatus.FILE_STATUS_UNREPORTED,
            condition_code=ConditionCode.NO_ERROR,
            pdu_conf=pdu_conf,
        )
        self.assertEqual(finish_pdu.delivery_code, DeliveryCode.DATA_COMPLETE)
        self.assertEqual(
            finish_pdu.file_delivery_status, FileDeliveryStatus.FILE_STATUS_UNREPORTED
        )
        self.assertEqual(finish_pdu.pdu_file_directive.packet_len, 9)
        finish_pdu_raw = finish_pdu.pack()
        self.assertEqual(len(finish_pdu_raw), 9)
        # 0x02 because the only parameters is the 0x05 directive code and the 0x03 from the file
        # delivery status
        self.assertEqual(
            finish_pdu_raw,
            bytes([0x20, 0x00, 0x02, 0x11, 0x00, 0x00, 0x00, 0x05, 0x03]),
        )
        finish_pdu_unpacked = FinishedPdu.unpack(raw_packet=finish_pdu_raw)
        self.assertEqual(finish_pdu_unpacked.delivery_code, DeliveryCode.DATA_COMPLETE)
        self.assertEqual(
            finish_pdu_unpacked.file_delivery_status,
            FileDeliveryStatus.FILE_STATUS_UNREPORTED,
        )
        self.assertEqual(finish_pdu_unpacked.pdu_file_directive.packet_len, 9)
        finish_pdu_repacked = finish_pdu_unpacked.pack()
        self.assertEqual(finish_pdu.pdu_file_directive.packet_len, 9)
        self.assertEqual(finish_pdu_repacked, finish_pdu_raw)
        finish_pdu_repacked = finish_pdu_repacked[:-1]
        self.assertRaises(
            ValueError, FinishedPdu.unpack, raw_packet=finish_pdu_repacked
        )

        invalid_fault_source = EntityIdTlv(entity_id=bytes([0x0]))
        finish_pdu_raw.extend(invalid_fault_source.pack())
        current_size = finish_pdu_raw[1] << 8 | finish_pdu_raw[2]
        current_size += invalid_fault_source.packet_len
        finish_pdu_raw[1] = (current_size & 0xFF00) >> 8
        finish_pdu_raw[2] = current_size & 0x00FF
        with self.assertRaises(ValueError):
            FinishedPdu.unpack(raw_packet=finish_pdu_raw)

        # Now generate a packet with a fault location
        fault_location_tlv = EntityIdTlv(entity_id=bytes([0x00, 0x02]))
        self.assertEqual(fault_location_tlv.packet_len, 4)
        finish_pdu_with_fault_loc = FinishedPdu(
            delivery_code=DeliveryCode.DATA_INCOMPLETE,
            file_delivery_status=FileDeliveryStatus.DISCARDED_DELIBERATELY,
            condition_code=ConditionCode.POSITIVE_ACK_LIMIT_REACHED,
            fault_location=fault_location_tlv,
            pdu_conf=pdu_conf,
        )
        self.assertEqual(
            finish_pdu_with_fault_loc.delivery_code, DeliveryCode.DATA_INCOMPLETE
        )
        self.assertEqual(
            finish_pdu_with_fault_loc.file_delivery_status,
            FileDeliveryStatus.DISCARDED_DELIBERATELY,
        )
        self.assertEqual(
            finish_pdu_with_fault_loc.condition_code,
            ConditionCode.POSITIVE_ACK_LIMIT_REACHED,
        )
        self.assertEqual(finish_pdu_with_fault_loc.fault_location, fault_location_tlv)
        # 4 additional bytes because the entity ID in the TLV has 2 bytes
        self.assertEqual(finish_pdu_with_fault_loc.packet_len, 13)
        self.assertEqual(len(finish_pdu_with_fault_loc.pack()), 13)
        self.assertEqual(finish_pdu_with_fault_loc.fault_location_len, 4)

        # Now create a packet with filestore responses
        filestore_reponse_1 = FileStoreResponseTlv(
            action_code=FilestoreActionCode.REMOVE_DIR_SNN,
            first_file_name="test.txt",
            status_code=FilestoreResponseStatusCode.REMOVE_DIR_SUCCESS,
        )
        filestore_response_1_packed = filestore_reponse_1.pack()
        self.assertEqual(
            filestore_response_1_packed,
            bytes(
                [
                    TlvTypes.FILESTORE_RESPONSE,
                    11,
                    0x60,
                    0x08,
                    0x74,
                    0x65,
                    0x73,
                    0x74,
                    0x2E,
                    0x74,
                    0x78,
                    0x74,
                    0x00,
                ]
            ),
        )
        self.assertEqual(filestore_reponse_1.packet_len, 13)
        pdu_with_response = FinishedPdu(
            delivery_code=DeliveryCode.DATA_INCOMPLETE,
            file_delivery_status=FileDeliveryStatus.DISCARDED_DELIBERATELY,
            condition_code=ConditionCode.FILESTORE_REJECTION,
            pdu_conf=pdu_conf,
            file_store_responses=[filestore_reponse_1],
        )
        self.assertEqual(pdu_with_response.packet_len, 22)
        pdu_with_response_raw = pdu_with_response.pack()
        expected_array = bytearray(
            [0x20, 0x00, 0x0F, 0x11, 0x00, 0x00, 0x00, 0x05, 0x44]
        )
        expected_array.extend(filestore_response_1_packed)
        self.assertEqual(expected_array, pdu_with_response_raw)
        pdu_with_response_unpacked = FinishedPdu.unpack(
            raw_packet=pdu_with_response_raw
        )
        self.assertEqual(len(pdu_with_response_unpacked.file_store_responses), 1)

        # Pack with 2 responses and 1 fault location
        first_file = "test.txt"
        second_file = "test2.txt"
        filestore_reponse_2 = FileStoreResponseTlv(
            action_code=FilestoreActionCode.APPEND_FILE_SNP,
            first_file_name=first_file,
            second_file_name=second_file,
            status_code=FilestoreResponseStatusCode.APPEND_NOT_PERFORMED,
        )
        fs_response_2_raw = filestore_reponse_2.pack()
        expected_reply = bytearray()
        expected_reply.extend(bytes([0x01, 0x15, 0x3F]))
        expected_reply.append(len(first_file))
        expected_reply.extend(first_file.encode())
        expected_reply.append(len(second_file))
        expected_reply.extend(second_file.encode())
        # 0 length filestore message
        expected_reply.append(0)
        self.assertEqual(filestore_reponse_2.packet_len, 23)
        self.assertEqual(fs_response_2_raw, expected_reply)
        finish_pdu_two_responses_one_fault_loc = FinishedPdu(
            delivery_code=DeliveryCode.DATA_COMPLETE,
            file_delivery_status=FileDeliveryStatus.FILE_RETAINED,
            condition_code=ConditionCode.CHECK_LIMIT_REACHED,
            pdu_conf=pdu_conf,
            file_store_responses=[filestore_reponse_1, filestore_reponse_2],
            fault_location=fault_location_tlv,
        )
        # length should be 13 (response 1) + 23 (response 2)  + 4 (fault loc) + 9 (base)
        self.assertEqual(finish_pdu_two_responses_one_fault_loc.packet_len, 49)
        fs_responses = finish_pdu_two_responses_one_fault_loc.file_store_responses
        self.assertEqual(len(fs_responses), 2)
        complex_pdu_raw = finish_pdu_two_responses_one_fault_loc.pack()
        complex_pdu_unpacked = FinishedPdu.unpack(raw_packet=complex_pdu_raw)
        self.assertEqual(
            complex_pdu_unpacked.fault_location.pack(), fault_location_tlv.pack()
        )
        self.assertEqual(filestore_reponse_1.pack(), fs_responses[0].pack())
        self.assertEqual(filestore_reponse_2.pack(), fs_responses[1].pack())

        # Change TLV type to make it invalid
        complex_pdu_raw[-5] = TlvTypes.FILESTORE_RESPONSE
        with self.assertRaises(ValueError):
            FinishedPdu.unpack(raw_packet=complex_pdu_raw)