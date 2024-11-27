from unittest import TestCase

from spacepackets.cfdp import MessageToUserTlv, TlvHolder, TlvType, TlvTypeMissmatchError
from spacepackets.cfdp.tlv import (
    CfdpTlv,
    ProxyMessageType,
    create_cfdp_proxy_and_dir_op_message_marker,
)


class TestMsgToUser(TestCase):
    def setUp(self) -> None:
        self.msg_to_usr_tlv = MessageToUserTlv(msg=bytes([0x00]))
        self.cfdp_tlv = CfdpTlv(self.msg_to_usr_tlv.tlv_type, self.msg_to_usr_tlv.value)

    def test_holder(self):
        wrapper = TlvHolder(self.msg_to_usr_tlv)
        msg_to_usr_tlv_from_fac = wrapper.to_msg_to_user()
        self.assertEqual(msg_to_usr_tlv_from_fac, self.msg_to_usr_tlv)

    def test_from_cfdp_tlv(self):
        self.assertEqual(TlvHolder(self.cfdp_tlv).to_msg_to_user(), self.msg_to_usr_tlv)

    def test_msg_to_user_tlv(self):
        msg_to_usr_tlv_tlv = self.msg_to_usr_tlv.tlv
        msg_to_usr_tlv_tlv.tlv_type = TlvType.FILESTORE_REQUEST
        with self.assertRaises(TlvTypeMissmatchError):
            MessageToUserTlv.from_tlv(cfdp_tlv=msg_to_usr_tlv_tlv)
        msg_to_usr_tlv_tlv.tlv_type = TlvType.MESSAGE_TO_USER
        msg_to_usr_tlv_raw = self.msg_to_usr_tlv.pack()
        msg_to_usr_tlv_unpacked = MessageToUserTlv.unpack(data=msg_to_usr_tlv_raw)
        self.assertEqual(msg_to_usr_tlv_unpacked.tlv.value, bytes([0x00]))
        self.assertFalse(msg_to_usr_tlv_unpacked.is_reserved_cfdp_message())
        proxy_val = bytearray(create_cfdp_proxy_and_dir_op_message_marker())
        proxy_val.append(ProxyMessageType.PUT_REQUEST)
        msg_to_usr_tlv = MessageToUserTlv(msg=proxy_val)
        self.assertTrue(msg_to_usr_tlv.is_reserved_cfdp_message())

    def test_invalid_conversion(self):
        self.assertIsNone(self.msg_to_usr_tlv.to_reserved_msg_tlv())
