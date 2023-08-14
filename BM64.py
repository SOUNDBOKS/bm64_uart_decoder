# High Level Analyzer for the BM64 UART protocol for the Saleae Logic Analyzer.
# This file implements the recognition of the different packet types and the decoding of the events and commands in those packets.

# This module is to be imported in Saleae Logic as an extension, and requires the  using the signals from the async serial analyzer.
# Each channel of the UART (RX/TX) needs to be configured with it's own BM64 Analyzer, and the configuration parameters should be set to RX/TX respectively.

# This module is inspired by the "UART HCI Decoder" analyzer by Brian Gomberg.

from abc import ABC
import struct
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting

# This is the command enumeration from MCU to BM64
BM64_COMMAND_DESC = {
    0x00: "Make_Call",
    0x01: "Make_Extension_Call",
    0x02: "MMI_Action",
    0x03: "Event_Mask_Setting",
    0x04: "Music_Control",
    0x05: "Change_Device_Name",
    0x06: "Change_PIN_Code",
    0x07: "BTM_Parameter_Setting",
    0x08: "Read_BTM_Version",
    0x09: "Get_PB_By_AT_Cmd",
    0x0A: "Vendor_AT_Command",
    0x0B: "AVC_Vendor_Dependent_Cmd",
    0x0C: "AVC_Group_Navigation",
    0x0D: "Read_Link_Status",
    0x0E: "Read_Paired_Device_Record",
    0x0F: "Read_Local_BD_Address",
    0x10: "Read_Local_Device_Name",
    0x11: "Set_Access_PB_Method",
    0x12: "Send_SPP",
    0x13: "BTM_Utility_Function",
    0x14: "Event_ACK",
    0x15: "Additional_Profiles_Link_Setup",
    0x16: "Read_Linked_Device_Information",
    0x17: "Profiles_Link_Back",
    0x18: "Disconnect",
    0x19: "MCU_Status_Indication",
    0x1A: "User_Confirm_SPP_Req_Reply",
    0x1B: "Set_HF_Gain_Level",
    0x1C: "EQ_Mode_Setting",
    0x1D: "DSP_NR_CTRL",
    0x1E: "GPIO_Control",
    0x1F: "MCU_UART_Rx_Buffer_Size",
    0x20: "Voice_Prompt_Cmd",
    0x21: "MAP_REQUEST",
    0x22: "Security_Bonding_Req",
    0x23: "Set_Overall_Gain",
    0x24: "Read_BTM_Setting",
    0x25: "Read_BTM_Batt_CHG_Status",
    0x26: "MCU_Update_Cmd",
    0x27: "REPORT_BATTERY_CAPACITY",
    0x28: "LE_ANCS_Service_Cmd",
    0x29: "LE_Signaling_Cmd",
    0x2A: "nSPK Vendor Cmd",
    0x2B: "Read_NSPK_Link_Status",
    0x2C: "NSPK_Sync_Audio_Effect",
    0x2D: "LE_GATT_CMD",
    0x2F: "LE_App_CMD",
    0x30: "DSP_RUNTIME_PROGRAM",
    0x31: "Read_Vendor_EEPROM_Data",
    0x32: "Query",
    0x33: "Voice_Prompt_Ind_Cmd",
    0x34: "Read_BTM_Link_Mode",
    0x35: "Configure_Vendor_Parameter",
    0x36: "DSP_Dedicated_Cmd",
    0x37: "nSPK",
    0x38: "UART_CMD_NSPK_SET_GIAC",
    0x39: "READ_FEATURE_LIST",
    0x3A: "Personal_MSPK_GROUP_Control",
    0x3B: "UART_CMD_TEST_DEVICE",
    0x40: "Reserved",
}

# This is the event enumeration from BM64 to MCU
BM64_EVENT_DESC = {
    0x00: "Command_ACK",
    0x01: "BTM_Status",
    0x02: "Call_Status",
    0x03: "Caller_ID",
    0x04: "SMS_Received_Indication",
    0x05: "Missed_Call_Indication",
    0x06: "Phone_Max_Battery_Level",
    0x07: "Phone_Current_Battery_Level",
    0x08: "Roaming_Status",
    0x09: "Phone_Max_Signal_Strength_Level",
    0x0A: "Phone_Current_Signal_Strength_Level",
    0x0B: "Phone_Service_Status",
    0x0C: "BTM_Battery_Status",
    0x0D: "BTM_Charging_Status",
    0x0E: "Reset_To_Default",
    0x0F: "Report_HF_Gain_Level",
    0x10: "EQ_Mode_Indication",
    0x11: "PBAP_Missed_Call_History",
    0x12: "PBAP_Received_Call_History",
    0x13: "PBAP_Dialed_Call_History",
    0x14: "PBAP_Combine_Call_History",
    0x15: "Phonebook_Contacts",
    0x16: "PBAP_Access_Finish",
    0x17: "Read_Linked_Device_Information_Reply",
    0x18: "Read_BTM_Version_Reply",
    0x19: "Call_List_Report",
    0x1A: "AVC_Specific_Rsp",
    0x1B: "BTM_Utility_Req",
    0x1C: "Vendor_AT_Cmd_Reply",
    0x1D: "Report_Vendor_AT_Event",
    0x1E: "Read_Link_Status_Reply",
    0x1F: "Read_Paired_Device_Record_Reply",
    0x20: "Read_Local_BD_Address_Reply",
    0x21: "Read_Local_Device_Name_Reply",
    0x22: "Report_SPP",
    0x23: "Report_Link_Back_Status",
    0x24: "REPORT_RING_TONE_STATUS",
    0x25: "User_Confrim_SSP_Req",
    0x26: "Report_AVRCP_Vol_Ctrl",
    0x27: "Report_Input_Signal_Level",
    0x28: "Report_iAP_Info",
    0x29: "REPORT_AVRCP_ABS_VOL_CTRL",
    0x2A: "Report_Voice_Prompt_Status",
    0x2B: "Report_MAP_Data",
    0x2C: "Security_Bonding_Res",
    0x2D: "Report_Type_Codec",
    0x2E: "Report_Type_BTM_Setting",
    0x2F: "Report_MCU_Update_Reply",
    0x30: "Report_BTM_Initial_Status",
    0x31: "LE_ANCS_Service_Event",
    0x32: "LE_Signaling_Event",
    0x33: "Report_nSPK_Link_Status",
    0x34: "Report_nSPK_Vendor_Event",
    0x35: "Report_nSPK_Audio_Setting",
    0x36: "Report_Sound_Effect_Status",
    0x37: "Report_Vendor_EEPROM_Data",
    0x38: "REPORT_IC_VERSION_INFO",
    0x39: "REPORT_LE_GATT_EVENT",
    0x3A: "Report_BTM_Link_Mode",
    0x3B: "DSP_Dedicated_Event",
    0x3C: "Report_nSPK_MISC_Event",
    0x3D: "Report_nSPK_Exchange_Link_Info",
    0x3E: "Report",
    0x3F: "Report_CSB_CLK",
    0x40: "Report_Read_Feature_List_Reply",
    0x41: "REPORT_TEST_RESULT_REPLY",
    0x50: "Reserved for internal use",
}


class BM64Cmd:
    def __init__(self, data):
        self.data = data

    def get_string(self):
        return f'{self.data}'


class LESignalingEvent(BM64Cmd):
    def get_string(self):
        le_signaling_sub_event_codes = {
            0x00: "LE Status Report",
            0x01: "LE Advertising Control Report",
            0x02: "LE Connection Parameter Report",
            0x03: "LE Connection Update RSP",
        }
        sub_cmd = self.data[0]
        string = le_signaling_sub_event_codes.get(sub_cmd, 'Unknown')
        if sub_cmd == 0x00:
            if self.data[1] == 0x00:
                status = 'Standby'
            elif self.data[1] == 0x01:
                status = 'Advertising'
            elif self.data[1] == 0x02:
                status = 'Scanning'
            elif self.data[1] == 0x03:
                status = 'Connected'
            string += f' - {status} - {self.data[2]}'
        elif sub_cmd == 0x01:
            if self.data[1] == 0x00:
                status = 'Command Succeeded'
            else:
                status = 'Command Failed'
            string += f' - {status}'
        return string


class ReportLEGATTEvent(BM64Cmd):
    def get_string(self):
        le_gatt_sub_event_codes = {
            0x00: "BLE_REC_CLIENT_WRITE_CHAR_VALUE",
            0x01: "BLE_REC_READ_LOCAL_CHAR_VALUE",
            0x02: "BLE_REC_DISCOVER_ALL_SERVICES",
            0x03: "BLE_REC_DISCOVER_CHARACTERISTICS_FOR_SERVICE",
            0x04: "BLE_REC_DISCOVER_CHARACTERISTIC_DESCRIPTORS",
            0x05: "BLE_REC_ATTRIBUTE_MTU_SIZE",
        }
        string = le_gatt_sub_event_codes.get(self.data[0], 'Unknown')
        if self.data[0] == 0x05:
            string += f' - MTU: {self.data[1]}'
        return string


class MMIAction(BM64Cmd):
    def get_string(self):
        mmi_action_decs = {
            0x01: "ADD_REMOVE_SCO_LINK",
            0x02: "FORCE_END_CALL",
            0x04: "ACCEPT_CALL",
            0x05: "REJECT_CALL",
            0x06: "ENDCALL_OR_TRANSFER_TO_HEADSET",
            0x07: "MIC_MUTE_TOGGLE",
            0x08: "MUTE_MIC",
            0x09: "UNMUTE_MIC",
            0x0A: "VOICE_DIAL",
            0x0B: "CANCLE_VOICE_DAIL",
            0x0C: "LAST_NUMBER_REDIAL",
            0x0D: "ACTIVE_CALL_HOLD_ACCEPT_HELD_CALL",
            0x0E: "VOICE_TRANSFER",
            0x0F: "QUERY_CALL_LIST",
            0x10: "THREE_WAY_CALL",
            0x11: "RELEASE_CALL",
            0x12: "ACCEPT_WAITING_HOLD_CALL_RLS_ACTIVE_CALL",
            0x16: "INITIAL_HF_CONNECTION",
            0x17: "DISCONNECT_HF_LINK",
            0x24: "INC_MIC_GAIN",
            0x25: "DEC_MIC_GAIN",
            0x26: "SWITCH_PRIMARY_SECONDARY_HF_DEVICE",
            0x30: "INC_SPK_GAIN",
            0x31: "DEC_SPK_GAIN",
            0x32: "INITIAL_A2DP_CONNECT_PLAY_PAUSE",
            0x33: "STOP_MEDIA",
            0x34: "NEXT_SONG",
            0x35: "PREVIOUS_SONG",
            0x3B: "DISCONNECT_A2DP",
            0x50: "STANDBY_ENTERING_PAIRING",
            0x51: "POWERON_BUTTON_PRESS",
            0x52: "POWERON_BUTTON_RELEASE",
            0x53: "POWEROFF_BUTTON_PRESS",
            0x54: "POWEROFF_BUTTON_RELEASE",
            0x56: "RESET_EEPROM_SETTING",
            0x5D: "ANY_MODE_ENTERING_PAIRING",
            0x5E: "POWEROFF_BT",
            0x60: "BUZZER_TOGGLE",
            0x61: "DISABLE_BUZZER",
            0x62: "ENABLE_BUZZER",
            0x63: "TONE_CHANGE",
            0x64: "RETRIEVE_PHONE_BOOK",
            0x65: "RETRIEVE_MISS_CALL_HISTORY",
            0x66: "RETRIEVE_RECEIVED_CALL_HISTORY",
            0x67: "RETRIEVE_DIALED_CALL_HISTORY",
            0x68: "RETRIEVE_ALL_CALL_HISTORY",
            0x69: "CANCLE_RETRIEVE",
            0x6A: "INDICATE_BATTERY_STATUS",
            0x6B: "EXIT_PAIRING_MODE",
            0x6C: "LINK_BACK_DEVICE",
            0x6D: "DISCONNECT_ALL_LINK",
            0xE0: "MASTERSPK_ENTER_CSB_PAGE",
            0xE1: "SLAVESPK_ENTER_CSB_PAGESCAN",
            0xE2: "NSPK_ADD_SPEAKER",
            0xE5: "MASTERSPK_TERMINAL_CSB",
            0xE7: "MASTERSPK_ENTER_AUXMODE",
            0xE8: "MASTERSPK_EXIT_AUXMODE",
            0xED: "POWER_OFF_ALL_SPK",
            0xF0: "MASTERSPK_REPAIR_TO_SLAVE",
        }

        return mmi_action_decs.get(self.data[1], 'Unknown')


class ChangeDeviceName(BM64Cmd):
    def get_string(self):
        return self.data[:-1].decode('utf-8')


class LESignalingCmd(BM64Cmd):
    def get_string(self):

        le_signaling_sub_cmd_types = {
            0x00: "Query LE status",
            0x01: "LE Advertising Control",
            0x02: "LE Connection Parameters Update REQ",
            0x03: "LE Advertising Interval Update",
            0x04: "LE Advertising Type",
            0x05: "LE Advertising Data",
            0x06: "LE Scan Response Data",
        }
        sub_cmd = self.data[0]
        string = le_signaling_sub_cmd_types.get(sub_cmd, 'Unknown')
        if sub_cmd == 0x01:
            if self.data[1] == 0x00:
                string += ' - Disable Advertising'
            else:
                string += '  - Enable Advertising'
        elif sub_cmd == 0x04:
            if self.data[1] == 0x00:
                cmd_type = 'Connectable undirected advertising.'
            elif self.data[1] == 0x01:
                cmd_type = 'Reserved'
            elif self.data[1] == 0x02:
                cmd_type = 'Scannable undirected advertising'
            elif self.data[1] == 0x03:
                cmd_type = 'Non connectable undirected advertising.'
            string += f' - {cmd_type}'
        elif sub_cmd == 0x05:
            string += f'  - {self.data[2:-1]}'
        elif sub_cmd == 0x06:
            string += f' - {self.data[2:-1]}'
        return string


class LEGATTCmd(BM64Cmd):
    def get_string(self):
        le_gatt_sub_cmd_type = {
            0x00: 'Send_Characteristic_Value',
            0x01: 'Send_Write_Response',
            0x02: 'Update_Characteristic_Value',
            0x03: 'Read_Local_Characteristic_Value',
            0x04: 'Read_Local_All_Primary_Services',
            0x05: 'Read_Local_Specific_Primary_Service',
        }
        sub_cmd = self.data[0]

        string = f'{le_gatt_sub_cmd_type[sub_cmd]}'
        if sub_cmd == 0x00:
            string += f' Connection Handle: {hex(self.data[1])} Charateristic Value Handle: {hex(self.data[2])} Charateristic Value: {hex(self.data[3])}'
        elif sub_cmd == 0x01:
            string += f' Connection Handle: {hex(self.data[1])} Request Opcode: {hex(self.data[2])} Attribute Handle: {self.data[3:5].hex()} Error Codes: {hex(self.data[5])}'
        elif sub_cmd == 0x02:
            string += f' Charateristic Value Handle: {self.data[1:3].hex()} Charateristic Value: {hex(self.data[3])}'

        return string


class LEAppCmd(BM64Cmd):
    def get_string(self):
        le_app_sub_cmd_type = {
            0x5c: 'Set_Device_Name',
            0x5d: 'Get_Att_MTU_Size',
        }
        sub_cmd = self.data[0]
        string = le_app_sub_cmd_type.get(sub_cmd, 'Unknown')
        if sub_cmd == 0x5c:
            string += f' - {self.data[2:-1].decode("utf-8")}'
        return string


class BTMParameterSetting(BM64Cmd):
    def bit_to_profile(self):
        data = self.data[1]
        string = ''
        if data & 1 << 0:
            string += 'HSP, '
        if data & 1 << 1:
            string += 'HFP, '
        if data & 1 << 2:
            string += 'A2DP, '
        if data & 1 << 3:
            string += 'AVRCP CT, '
        if data & 1 << 4:
            string += 'AVRCP TG, '
        if data & 1 << 5:
            string += 'SPP, '
        if data & 1 << 6:
            string += 'iAP, '
        if data & 1 << 7:
            string += 'PBAP, '
        return string

    def get_string(self):
        btm_parameter_setting_parameter = {
            0x00: "Set Pairing Timeout Value",
            0x01: "Set Supported A2DP Codec Type(This change will stored in device)",
            0x02: "Enable/Disable BTM Standby Mode (This change will update the e2prom)",
            0x03: "Set The Recharging Battery Capacity Threshold",
            0x04: "Set Supported BT Classic Profile",
            0x05: "Set SBC bitpool setting : this should be set before A2DP connection established",
            0x06: "Setting iAP2 serial number (This change will stored in device)",
        }
        sub_cmd = self.data[0]
        if sub_cmd == 0x04:
            string = f'{btm_parameter_setting_parameter[sub_cmd]}' + \
                ": " + self.bit_to_profile()

        return string


class BTMUtilityFunction(BM64Cmd):
    def get_string(self):
        btm_utility_function = {
            0x00: 'Host MCU ask BTM to process NFC detected function.',
            0x01: 'To Enable/Disable in-built Aux Line In Function',
            0x02: 'To generate one-shot specific tone',
            0x03: 'To make BTM on-discoverable and non-connectable or active',
            0x04: 'To indicate charger adaptor status',
            0x05: 'To indicate BTM that remote device supports TTS engine. The BTM shall disable internal TTS engine.',
            0x06: 'To update partial EEPROM data which are related to part of audio configuration.',
            0x07: 'Voice prompt for the given version number.',
            0x08: 'For MSPK, MCU notifies the BTM current power condition',
            0x09: 'To update vendor EEPROM data',
            0x0A: 'For MSPK, To inform Central that certain status has been changed in Peripheral side',
            0x0B: 'To Read Serial number. For this command, MCU will receive event Report_Vendor_EEPROM_Data with report data 16 bytes.',
            0x0C: 'To switch audio channel',
            0x0D: 'Customized MCU report : MCU Report specified information the following parameter',
            0x0E: 'Customized MCU request: MCU request specified information by the following parameter. BTM replies the specified information by E3E',
            0x0F: 'To enable MIC loopback as Line-in',
        }

        sub_cmd = self.data[0]
        string = f'{btm_utility_function[sub_cmd]}'
        if sub_cmd == 0x01:
            if self.data[1] == 0x00:
                string += ' - Line in is not controlled by MCU'
            else:
                string += ' - Line in is controlled by MCU'

        return string


class ReportTypeCodec(BM64Cmd):
    def get_string(self):
        parameter = {
            0x00: '8KHz sample rate',
            0x02: '16KHz sample rate',
            0x04: '32KHz sample rate',
            0x05: '48KHz sample rate',
            0x06: '44.1KHz sample rate',
            0x07: '88KHz sample rate',
            0x08: '96KHz sample rate',
        }
        sub_cmd = self.data[0]
        return parameter.get(sub_cmd, 'Unknown')


class BTMStatus(BM64Cmd):
    def get_string(self):
        parameter = {
            0x00: 'Power OFF state',
            0x01: 'Pairing state (discoverable mode)',
            0x02: 'Power ON state',
            0x03: 'Pairing successful',
            0x04: 'Pairing failed',
            0x05: 'HF/HS link established',
            0x06: 'A2DP link established',
            0x07: 'HF link disconnected',
            0x08: 'A2DP link disconnected',
            0x09: 'SCO link connected',
            0x0A: 'SCO link disconnected',
            0x0B: 'AVRCP link established',
            0x0C: 'AVRCP link disconnected',
            0x0D: 'Standard SPP connected',
            0x0E: 'Standard_SPP / iAP disconnected',
            0x0F: 'Standby state',
            0x10: 'iAP connected',
            0x11: 'ACL disconnected',
            0x12: 'MAP connected',
            0x13: 'MAP operation forbidden',
            0x14: 'MAP disconnected',
            0x15: 'ACL connected',
            0x16: 'SPP / iAP disconnected no_other Profile',
            0x17: 'Link back ACL (BT paging)',
            0x18: 'Inquiry State',
            0x80: 'Current audio source is not Aux in or A2DP',
            0x81: 'Current audio source is Aux in',
            0x82: 'Current audio source is A2DP',
        }

        sub_cmd = self.data[0]
        string = parameter.get(sub_cmd, "unknown")
        if sub_cmd == 0x02:
            if self.data[1] == 0x01:
                string += ' - Already power on'
        elif sub_cmd == 0x03:
            string += f' - Current link id: {hex(self.data[1:-1])}'
        elif sub_cmd == 0x04:
            if self.data[1] == 0x00:
                string += ' - Time out'
            elif self.data[1] == 0x01:
                string += ' - Fail'
            elif self.data[1] == 0x02:
                string += ' - Exit paring mode'

        return string


class BTMUtilityReq(BM64Cmd):
    def get_string(self):
        btm_utility_request = {
            0x00: 'BTM ask MCU to control the external amplifier',
            0x01: 'BTM report the Aux line-in status to Host MCU.',
            0x02: 'BTM notify MCU to handle BTM or MCU update process',
            0x03: 'BTM notify MCU eeprom update finish',
            0x04: 'BTM report the A2DP codec status to Host MCU.',
            0x05: '[MSPK] BTM notify MCU to sync power off BTM',
            0x06: '[MSPK] BTM notify MCU to sync Volume Control',
            0x07: '[MSPK] BTM notify MCU to sync internal gain',
            0x08: '[MSPK] BTM notify MCU to sync A2DP absolute volume',
            0x09: '[MSPK] BTM notify MCU current channel setting',
            0x0A: '[MSPK] BTM notify MCU synced MSPK power condition',
            0x0B: '[MSPK] BTM notify MCU MSPK command success',
            0x0C: '[MSPK] BTM notify MCU MSPK command fail',
            0x0D: '[MSPK] BTM notify MCU certain MSPK Peripheral status has been changed',
            0x0E: 'Reserved',
            0x0F: 'Reserved',
            0x10: 'Reserved',
            0x11: '[MSPK] BTM notify MCU to sync Line-in absolute volume',
            0x12: '[MSPK] BTM notify MCU that MSPK connection complete.',
            0x13: 'BTM reports AVDTP start state to Host MCU.',
            0x14: 'BTM reports AVDTP suspend state to Host MCU.',
        }
        return btm_utility_request.get(self.data[0], 'Unknown')


class ReadLinkStatusReply(BM64Cmd):
    def get_string(self):
        parameter = {
            0x00: 'Power OFF state',
            0x01: 'pairing state (discoverable mode)',
            0x02: 'standby state',
            0x03: 'Connected state with only HF profile connected',
            0x04: 'Connected state with only A2DP profile connected',
            0x05: 'Connected state with only SPP profile connected',
            0x06: 'Connected state with multi-profile connected',
        }
        return parameter.get(self.data[0], 'Unknown')


class Packet(ABC):
    HEADER_FMT = None
    PKG_LENGTH_INDEX = None
    PKG_LENGTH_FMT = None

    def __init__(self):
        assert self.HEADER_FMT
        assert self.PKG_LENGTH_FMT
        self._header_temp = b''
        self._header = None
        self._data = b''
        self._pkg_length = None

    def process_data(self, data):
        while data:
            if not self._header:
                # Find the header size of this packet
                header_size = struct.calcsize(self.HEADER_FMT)
                new_header_bytes = min(
                    header_size - len(self._header_temp), len(data))

                # Shift the data into the header
                self._header_temp += data[:new_header_bytes]
                data = data[new_header_bytes:]

                if len(self._header_temp) < header_size:
                    # Not enough data to decode the header
                    assert len(data) == 0
                    return False

                # Decode the header
                self._header = struct.unpack(
                    self.HEADER_FMT, self._header_temp)

                # Get the length of the rest of the package, using the package defined length format
                self._pkg_length = struct.unpack(
                    self.PKG_LENGTH_FMT,
                    self._header_temp[
                        self.PKG_LENGTH_INDEX: self.PKG_LENGTH_INDEX + struct.calcsize(self.PKG_LENGTH_FMT)]
                )[0]

            # Load the data bytes
            self._data += data

            assert self._pkg_length is not None
            # Only return true if we have the full packet
            return len(self._data) >= self._pkg_length

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        pass


class HCICommandPacket(Packet):
    HEADER_FMT = "<HB"
    PKG_LENGTH_INDEX = 2
    PKG_LENGTH_FMT = "B"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        # BM64 HCI Command Enumeration
        hci_command_description = {
            0x1005: "Read Buffer Size",
            0x0c33: "Host Buffer Size",
            0x0405: "Create Connection Command",
            0x0406: "Disconnect Connection Command",
        }

        opcode, param_len = self._header

        return AnalyzerFrame('hci_cmd', start_time, end_time, {
            'packet_type': "HCI Command",
            'operation': hci_command_description.get(opcode, "Unknown Opcode"),
            'opcode': opcode,
            'length': param_len,
        })


class HCIISDAPCmd:
    ''' A common class for ISDAP commands, however each individual command will have its own class.'''

    def __init__(self, data, opcode, length):
        # ISDAP Header
        self.data = data
        self.opcode = opcode
        self.length = length

    def get_opcode_string(self, opcode):
        ''' Get the opcode string from the opcode enumeration'''
        isdap_command_desc = {
            0x001: "Write Continue Memory Command",
            0x100: "Lock / Unlock Memory Command",
            0x110: "Read Memory Command",
            0x111: "Write Memory Command",
            0x112: "Erase Memory Command",
            0x114: "Get Memory CRC Command",
        }

        return isdap_command_desc.get(opcode, "Unknown Opcode")

    def get_analyzer_frame(self, start_time, end_time):
        ''' Default analyzer frame for ISDAP commands if not specifically handled in seperate class.'''
        return AnalyzerFrame('hci_isdap', start_time, end_time, {
            'packet_type': "HCI Event",
            'operation': self.get_opcode_string(self.opcode),
            'isdap_opcode': self.opcode,
            'isdap_length': self.length,
        })


class HCIISDAPPacket(Packet):
    HEADER_FMT = "<HH"
    PKG_LENGTH_INDEX = 2
    PKG_LENGTH_FMT = "<H"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):

        # Check if we have the ISDAP header
        if len(self._data) >= 4:
            # Get the data.
            isdap_opcode, isdap_length = struct.unpack(
                "<HH", self._data[:struct.calcsize("<HH")])

            # Move the data pointer to after isdap opcode and length
            self._data = self._data[struct.calcsize("<HH"):]

            if rx_channel:
                # If this is from the BM64, then this is a response with command result
                return HCIISDAPResponse(self._data, isdap_opcode, isdap_length).get_analyzer_frame(start_time, end_time)
            else:
                if isdap_opcode == 0x001:    # Write memory command
                    return HCIISDAPWriteContinueMemory(self._data, isdap_opcode, isdap_length).get_analyzer_frame(start_time, end_time)
                elif isdap_opcode == 0x111:  # Write continue memory command
                    return HCIISDAPWriteMemory(self._data, isdap_opcode, isdap_length).get_analyzer_frame(start_time, end_time)

        # Default if not handled previously
        return AnalyzerFrame('hci_isdap', start_time, end_time, {
            'packet_type': "HCI-ISDAP",
            'operation': HCIISDAPCmd(self._data, isdap_opcode, isdap_length).get_opcode_string(isdap_opcode),
            'isdap_opcode': isdap_opcode,
            'isdap_length': isdap_length,
            'data': self._data,
        })


class HCIISDAPWriteMemory(HCIISDAPCmd):
    def get_analyzer_frame(self, start_time, end_time):
        # Check if the write flag is set.
        if self.length & 0x8000:
            write_flag = True
            # First bit is a flag
            self.length = self.length - 0x8000
        else:
            write_flag = False

        # Get the isdap command parameters
        isdap_memory_type, isdap_sub_memory_type,  = struct.unpack(
            "BB", self.data[0:struct.calcsize("BB")])
        isdap_bank_addr, isdap_bank = struct.unpack(
            "<HH", self.data[struct.calcsize("BB"):struct.calcsize("<BBHH")])
        isdap_packet_write_bytes, isdap_transfer_write_bytes,  = struct.unpack(
            "<HH", self.data[struct.calcsize("<BBHH"):struct.calcsize("<BBHHHH")])

        # Set the data pointer.
        self.data = self.data[struct.calcsize("<BBHHHH"):]

        return AnalyzerFrame('hci_isdap_write_memory', start_time, end_time, {
            'packet_type': "HCI-ISDAP Write Memory",
            'operation': self.get_opcode_string(self.opcode),
            'isdap_opcode': self.opcode,
            'isdap_length': self.length,
            'isdap_memory_type': isdap_memory_type,
            'isdap_sub_memory_type': isdap_sub_memory_type,
            'isdap_write_bank': isdap_bank,
            'isdap_write_bank_addr': isdap_bank_addr,
            'isdap_packet_write_bytes': isdap_packet_write_bytes,
            'isdap_transfer_write_bytes': isdap_transfer_write_bytes,
            'write_continue_flag': write_flag,
            'data': self.data,
            'data_length': len(self.data),
        })


class HCIISDAPWriteContinueMemory(HCIISDAPCmd):
    def get_analyzer_frame(self, start_time, end_time):
        # Check if the write flag is set.
        if self.length & 0x8000:
            write_flag = True
            # First bit is a flag
            self.length = self.length - 0x8000
        else:
            write_flag = False

        return AnalyzerFrame('hci_isdap_write_continue_memory', start_time, end_time, {
            'packet_type': "HCI-ISDAP  Write Continue Memory",
            'operation': self.get_opcode_string(self.opcode),
            'isdap_opcode': self.opcode,
            'isdap_length': self.length,
            'write_continue_flag': write_flag,
            'data': self.data,
            'data_length': len(self.data),
        })


class HCIISDAPResponse(HCIISDAPCmd):
    def get_analyzer_frame(self, start_time, end_time):
        # Check the status message
        result = struct.unpack("<H", self.data[:struct.calcsize("<H")])[0]

        # Move the data pointer to after result
        self.data = self.data[struct.calcsize("<H"):]

        return AnalyzerFrame('hci_isdap_response', start_time, end_time, {
            'packet_type': "HCI-ISDAP Response",
            'operation': self.get_opcode_string(self.opcode),
            'isdap_opcode': self.opcode,
            'isdap_length': self.length,
            'isdap_result': "success" if result == 0 else result,
            'data': self.data,
        })


class HCIEventPacket(Packet):
    HEADER_FMT = "BB"
    PKG_LENGTH_INDEX = 1
    PKG_LENGTH_FMT = "B"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        # BM64 HCI Event Enumeration
        hci_event_desc = {
            0x03: "Connection Complete Event",
            0x05: "Disconnect Complete Event",
            0x0E: "Command Complete Event",
            0x0F: "Command Status Event",
            0x13: "Number of Completed Packet Event",
        }
        event_code, _ = self._header
        event_string = hci_event_desc[event_code]

        return AnalyzerFrame('hci_event', start_time, end_time, {
            'packet_type': "HCI Event",
            'operation': event_string,
        })


class BM64RXPacket(Packet):
    HEADER_FMT = ">HB"
    PKG_LENGTH_INDEX = 0
    PKG_LENGTH_FMT = ">H"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        # Readout info from header
        _, event_code = self._header
        event_string = 'Unknown Event'
        # Check if we are configured to commands or events
        if not rx_channel:
            event_string = BM64_COMMAND_DESC[event_code]
            if event_code == 0x02:
                data_string = MMIAction(self._data).get_string()
            elif event_code == 0x05:
                data_string = ChangeDeviceName(self._data).get_string()
            elif event_code == 0x07:
                data_string = BTMParameterSetting(self._data).get_string()
            elif event_code == 0x0d:
                data_string = ""
            elif event_code == 0x0f:
                data_string = ""
            elif event_code == 0x10:
                data_string = ""
            elif event_code == 0x13:
                data_string = BTMUtilityFunction(self._data).get_string()
            elif event_code == 0x14:
                data_string = f'{BM64_EVENT_DESC[self._data[0]]}'
            elif event_code == 0x29:
                data_string = LESignalingCmd(self._data).get_string()
            elif event_code == 0x2d:
                data_string = LEGATTCmd(self._data).get_string()
            elif event_code == 0x2f:
                data_string = LEAppCmd(self._data).get_string()
            else:
                data_string = 'Not implemented event code: ' + \
                    str(hex(event_code))
            return AnalyzerFrame('bm64', start_time, end_time, {
                'packet_type': "BM64 Command",
                'event': event_string,
                'data': data_string,
            })


class BM64TXPacket(Packet):
    HEADER_FMT = ">BHB"
    PKG_LENGTH_INDEX = 1
    PKG_LENGTH_FMT = ">H"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        # Readout info from header
        _, _, event_code = self._header
        event_string = 'Unknown Event'
        # Check if we are configured to commands or events
        if rx_channel:
            data = self._data
            data_string = ''
            event_string = BM64_EVENT_DESC[event_code]
            if event_code == 0x00:
                data_string = BM64_COMMAND_DESC[data[0]]
                if data[1] == 0x00:
                    data_string += ' - Command complete: BTM can handle this command.'
                elif data[1] == 0x01:
                    data_string += ' - Command disallow:: BTM cannot handle this command.'
                elif data[1] == 0x02:
                    data_string += ' - Unknown command'
                elif data[1] == 0x03:
                    data_string += ' - Parameters error'
                elif data[1] == 0x04:
                    data_string += ' - BTM is busy'
                elif data[1] == 0x05:
                    data_string += ' - BTM memory is full'
            elif event_code == 0x01:
                data_string = BTMStatus(data).get_string()
            elif event_code == 0x1b:
                data_string = BTMUtilityReq(data).get_string()
            elif event_code == 0x1e:
                data_string = ReadLinkStatusReply(data).get_string()
            elif event_code == 0x20:
                data_string = data[::-1][1:].hex()
            elif event_code == 0x21:
                data_string = data[1:-1].decode('utf-8')
            elif event_code == 0x2d:
                data_string = ReportTypeCodec(data).get_string()
            elif event_code == 0x30:
                data_string = "Initialization complete"
            elif event_code == 0x32:
                data_string = LESignalingEvent(data).get_string()
            elif event_code == 0x39:
                data_string = ReportLEGATTEvent(data).get_string()
            else:
                data_string = 'Not implemented event code: ' + \
                    str(hex(event_code))

            return AnalyzerFrame('bm64', start_time, end_time, {
                'packet_type': "BM64 Event",
                'event': event_string,
                'data': data_string,
            })


# Define all the supported packets by their type
PACKETS = {
    0x00: BM64TXPacket,  # A bm64 package with wakeup b'0x00
    0x01: HCICommandPacket,
    0x02: HCIISDAPPacket,
    0x04: HCIEventPacket,
    0xAA: BM64RXPacket,
}


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    result_types = {
        'bm64': {
            'format': '{{data.packet_type}} - {{data.event}} ({{data.data}})'
        },
        'hci_event': {
            'format': '{{data.packet_type}} ({{data.operation}})'
        },
        'hci_cmd': {
            'format': '{{data.packet_type}} ({{data.operation}}:({{data.opcode}} | length={{data.length}})'
        },
        'hci_isdap': {
            'format': '{{data.packet_type}} (\'{{data.operation}}\', isdap_length=[{{data.isdap_length}}], isdap_result=\'{{data.isdap_result}})\''
        },
        'hci_isdap_write_memory': {
            'format': '{{data.packet_type}} (\'{{data.operation}}\', continue:\'{{data.write_continue_flag}}\', data_length=[{{data.data_length}}])\''
        },
        'hci_isdap_response': {
            'format': '{{data.packet_type}} (\'{{data.operation}}\', isdap_result=\'{{data.isdap_result}}, isdap_length=[{{data.isdap_length}}])\''
        },
        'hci_isdap_write_continue_memory': {
            'format': '{{data.packet_type}} (\'{{data.operation}}\', continue:\'{{data.write_continue_flag}}\', data_length=[{{data.data_length}}]})\''
        },
    }

    # As there is no protocol difference in the BM64 commands vs events, we need to detect the direction of the communication.
    Channel_Configuration = ChoicesSetting(
        ['Autodetect', 'MCU -> BM64 (TX)', 'BM64 -> MCU (RX)'])
    # Default
    rx_channel = None
    # Override
    if Channel_Configuration == 'MCU -> BM64':
        rx_channel = False
    elif Channel_Configuration == 'BM64 -> MCU':
        rx_channel = True

    def __init__(self):
        self._packet = None
        self._start_time = None
        self._last_byte = b''

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        # Error checking on incoming byte
        if frame.type != 'data':
            # Only care about data frame
            return
        if 'error' in frame.data:
            # Ignore error frames (i.e. framing / parity errors)
            return

        # Load byte

        data = frame.data['data']

        # Process the data
        if not self._packet:
            # This is the start of a new packet - determine the type based on the first byte
            packet_class = PACKETS.get(data[0], None)

            if not packet_class:
                self._last_byte = data
                return AnalyzerFrame('unknown', frame.start_time, frame.end_time, {})
            elif self.Channel_Configuration == 'Autodetect' \
                    and self.rx_channel is None \
                    and packet_class == HCIEventPacket:

                self.rx_channel = True

            elif self.Channel_Configuration == 'Autodetect' \
                    and self.rx_channel is None \
                    and packet_class == BM64TXPacket:

                self.rx_channel = True

            self._start_time = frame.start_time
            self._packet = packet_class()

        elif self._packet.process_data(data):
            # This is the end of the packet signalled by the packet class
            result = self._packet.get_analyzer_frame(
                self._start_time, frame.end_time, self.rx_channel)

            # reset variables
            self._packet = None
            self._start_time = None
            self._last_byte = data

            # post the result
            return result
