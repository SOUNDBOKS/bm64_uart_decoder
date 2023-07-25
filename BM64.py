# This is a High Level Analyzer for the BM64 UART protocol for the Saleae Logic Analyzer.
# This file implements the recognition of the different packet types and the decoding of the events and commands in those packets.

# This module is to be imported in Saleae Logic as an extension, and requires the  using the signals from the async serial analyzer.
# Each channel of the UART (RX/TX) needs to be configured with it's own BM64 Analyzer, and the configuration parameters should be set to RX/TX respectively.

# This module is inspired by the "UART HCI Decoder" analyzer by Brian Gomberg.

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting
from abc import ABC
import struct

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

# BM64 HCI Command Enumeration
HCI_COMMAND_DESC = {
    0x1005: "Read Buffer Size",
    0x0c33: "Host Buffer Size",
    0x0405: "Create Connection Command",
    0x0406: "Disconnect Connection Command",
}

# BM64 HCI Event Enumeration
HCI_EVENT_DESC = {
    0x03: "Connection Complete Event",
    0x05: "Disconnect Complete Event",
    0x0E: "Command Complete Event",
    0x0F: "Command Status Event",
    0x13: "Number of Completed Packet Event",
}

# ISDAP Command Enumeration
ISDAP_COMMAND_DESC = {
    0x001: "Write Continue Memory Command",
    0x100: "Lock / Unlock Memory Command",
    0x111: "Write Memory Command",
    0x112: "Erase Memory Command",
}

class Packet(ABC):
    HEADER_FMT = None
    RESULT_TYPES = None
    PKG_LENGTH_INDEX = None
    PKG_LENGTH_FMT = None

    def __init__(self):
        assert self.HEADER_FMT
        assert self.PKG_LENGTH_FMT
        self._header_temp = b''
        self._header = None
        self._data = b''

    def process_data(self, data):
        while data:
            if not self._header:
                # Find the header size of this packet
                header_size = struct.calcsize(self.HEADER_FMT)
                new_header_bytes = min(header_size - len(self._header_temp), len(data))

                # Shift the data into the header
                self._header_temp += data[:new_header_bytes]
                data = data[new_header_bytes:]

                if len(self._header_temp) < header_size:
                    # Not enough data to decode the header
                    assert len(data) == 0
                    return False

                # Decode the header
                self._header = struct.unpack(self.HEADER_FMT, self._header_temp)

                # Get the length of the rest of the package, using the package defined length format
                self._pkg_length = struct.unpack(self.PKG_LENGTH_FMT, self._header_temp[self.PKG_LENGTH_INDEX:self.PKG_LENGTH_INDEX + struct.calcsize(self.PKG_LENGTH_FMT)])[0]

            # Load the data bytes
            self._data += data

            # Only return true if we have the full packet
            return len(self._data) >= self._pkg_length

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        pass

class HCICommandPacket(Packet):
    HEADER_FMT = "<HB"
    RESULT_TYPES = {'hci_cmd': "{{data.packet_type}} ({{data.operation}}:({{data.opcode}} | length={{data.length}})"}
    PKG_LENGTH_INDEX = 2
    PKG_LENGTH_FMT = "B"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        opcode, param_len = self._header
        return AnalyzerFrame('hci_cmd', start_time, end_time, {
            'packet_type': "HCI Command",
            'operation': HCI_COMMAND_DESC.get(opcode, "Unknown Opcode"),
            'opcode': opcode,
            'length': param_len,
        })

class HCIISDAPFlashPacket(Packet):
    HEADER_FMT = "<HH"
    RESULT_TYPES = {'hci_isdap': "{{data.packet_type}} (\'{{data.operation}}\', isdap_length=[{{data.isdap_length}}], isdap_result=\'{{data.isdap_result}})\'"}
    PKG_LENGTH_INDEX = 2
    PKG_LENGTH_FMT = "<H"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        result = 'unknown'
        write_flag = 'unknown'
        # Check if we have the ISDAP header
        if len(self._data) >= 4:
            # Get the data.
            isdap_opcode, isdap_length = struct.unpack("<HH", self._data[:4])

            # Set pointer
            self._data = self._data[4:]

            if(rx_channel == True):
                # Check the status message
                result = struct.unpack("<H", self._data[:2])[0]
            else:
                result = 'NA'
                if(isdap_opcode in [0x001, 0x111]): # Write memory command
                    if isdap_length & 0x8000:
                        write_flag = True
                        # First bit is a flag
                        isdap_length = isdap_length - 0x8000
                    else:
                        write_flag = False

                    self._data = self._data[4:]
        return AnalyzerFrame('hci_isdap', start_time, end_time, {
            'packet_type': "HCI-ISDAP",
            'isdap_opcode': isdap_opcode,
            'operation': ISDAP_COMMAND_DESC.get(isdap_opcode, "Unknown ISDAP Opcode"),
            'isdap_length': isdap_length,
            'write_flag': write_flag,
            'isdap_result': "success" if result == 0 else result,
            'data' : self._data,
        })

class HCIEventPacket(Packet):
    HEADER_FMT = "BB"
    RESULT_TYPES = {'hci_event': "{{data.packet_type}} ({{data.operation}})"}
    PKG_LENGTH_INDEX = 1
    PKG_LENGTH_FMT = "B"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        event_code, length = self._header
        if event_code in HCI_EVENT_DESC:
            event_str = HCI_EVENT_DESC[event_code]
        else:
            event_str = f"Unknown Event"
        return AnalyzerFrame('hci_event', start_time, end_time, {
            'packet_type': "HCI Event",
            'operation': event_str,
        })

class BM64Packet(Packet):
    HEADER_FMT = ">HB"
    RESULT_TYPES = {'bm64': "{{data.packet_type}} ({{data.opcode}}) ({{data.operation}}) ({{data.packet_length}})"}
    PKG_LENGTH_INDEX = 0
    PKG_LENGTH_FMT = ">H"

    def get_analyzer_frame(self, start_time, end_time, rx_channel):
        # Readout info from header
        length, event_code = self._header
        event_str = f"Unknown Event"
        # Check if we are configured to commands or events
        if(rx_channel != True):
            if event_code in BM64_COMMAND_DESC:
                event_str = BM64_COMMAND_DESC[event_code]
            return AnalyzerFrame('bm64', start_time, end_time, {
                'packet_type': "BM64 Command",
                'opcode': event_code,
                'operation': event_str,
                'packet_length': length,
            })
        else:
            if event_code in BM64_EVENT_DESC:
                event_str = BM64_EVENT_DESC[event_code]
            return AnalyzerFrame('bm64', start_time, end_time, {
                'packet_type': "BM64 Event",
                'operation': event_str,
                'packet_length': length,
            })

# Define all the supported packets by their type
PACKETS = {
    0x01: HCICommandPacket,
    0x02: HCIISDAPFlashPacket,
    0x04: HCIEventPacket,
    0xAA: BM64Packet,
}

# Collect all the result types
RESULT_TYPES = {}
for p in PACKETS.values():
    RESULT_TYPES.update({k: {'format': v} for k, v in p.RESULT_TYPES.items()})

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # As there is no protocol difference in the BM64 commands vs events, we need to detect the direction of the communication.
    Channel_Configuration = ChoicesSetting(['Autodetect', 'MCU -> BM64 (TX)', 'BM64 -> MCU (RX)'])
    # Default
    rx_channel = None
    # Override
    if(Channel_Configuration == 'MCU -> BM64'):
        rx_channel = False
    elif (Channel_Configuration == 'BM64 -> MCU'):
        rx_channel = True

    # Result types based on the packet types
    result_types = RESULT_TYPES

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
            elif self.Channel_Configuration == 'Autodetect' and self.rx_channel == None and packet_class == HCIEventPacket:
                print("Detected to be an RX line by HCI Event.")
                self.rx_channel = True
            elif self.Channel_Configuration == 'Autodetect' and self.rx_channel == None and packet_class == BM64Packet and self._last_byte == b'\x00':
                print("Detected to be an RX line by BM64 0x00 wake byte.")
                self.rx_channel = True

            self._start_time = frame.start_time
            self._packet = packet_class()

        elif self._packet.process_data(data):
            # This is the end of the packet signalled by the packet class
            result = self._packet.get_analyzer_frame(self._start_time, frame.end_time, self.rx_channel)

            # reset variables
            self._packet = None
            self._start_time = None
            self._last_byte = data

            # post the result
            return result
