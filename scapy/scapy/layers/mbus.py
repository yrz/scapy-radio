# -*- coding: utf-8 -*-
## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus Defence and Space
## Authors: Jean-Michel Huguet, Adam Reziouk, Jonathan-Christofer Demay
## This program is published under a GPLv2 license


"""
M-Bus.
Inspired from:
   http://www.m-bus.com/files/w4b21021.pdf
   https://github.com/CBrunsch/scambus
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.mbus_enums import *

class MBusDIF(Packet):
    __slots__ = [ "ndifs" ]
    name = "MBus DIF"
    fields_desc = [
        BitEnumField("extension", 0, 1, DIF_extension),
        BitField("storage", 0, 1),
        BitEnumField("function", 0, 2, DIF_function),
        BitEnumField("data_info", 0, 4, DIF_data_info)
    ]

    
    def get_nvifs(self):
        return self.ndifs

    def pre_dissect(self, s):
        self.ndifs = 0;
        for i in s: #count DIFs
            if (ord(i) & 0x80):
                self.ndifs += 1
            else: #Last DIF
                break
        return s


    def guess_payload_class(self, payload):
        return Padding

class MBusDIFe(Packet):
    name = "MBus Extended DIF"
    fields_desc = [
        BitEnumField("extension", 0, 1, DIF_extension),
        BitEnumField("unit", 0, 1, DIFE_unit),
        BitEnumField("tariff", 0, 2, DIFE_tariff),
        BitEnumField("data_info", 0, 4, DIF_data_info)
    ]

    def guess_payload_class(self, payload):
        return Padding



class MBusVIF(Packet):
    __slots__ = [ "nvifs" ]
    name = "MBus VIF"
    fields_desc = [
        BitEnumField("extension", 0, 1, VIF_extension),
        BitEnumField("unit", "Reserved", 7, VIF_Main)
    ]
    
    def get_nvifs(self):
        return self.nvifs

    def pre_dissect(self, s):
        self.nvifs = 0;

        for i in s: #count VIFs
            if (ord(i) & 0x80):
                self.nvifs += 1
            else:
                break
        return s


    def guess_payload_class(self, payload):
        if self.extension:
            if self.unit == 0x7C:
                return Padding
            if self.unit == 0x7B:
                return MBusVIFe_List_Ext2
            if self.unit == 0x7D:
                return MBusVIFe_List_Ext1
            if self.unit == 0x7E:
                return Padding
            return MBusVIFe_List_Main
        
        return Padding
    

######### VIFE Main #########
class MBusVIFe_Main(Packet):
    name = "MBus VIF"
    fields_desc = [
        BitEnumField("extension", 0, 1, VIF_extension),
        BitEnumField("unit", "Reserved", 7, VIF_Main),
    ]

    def guess_payload_class(self, payload):
        return Padding

class MBusVIFe_List_Main(Packet):
    name = "MBus VIFE list MAIN"
    fields_desc = [
        PacketListField("VIFe", MBusVIFe_Main(), MBusVIFe_Main, count_from=lambda pkt: pkt.underlayer.get_nvifs())
    ]


######### VIFE Extended 1 #########
class MBusVIFe_Ext1(Packet):
    name = "MBus VIF1"
    fields_desc = [
        BitEnumField("extension", 0, 1, VIF_extension),
        BitEnumField("unit", "Reserved", 7, VIFe_ext1),
    ]
    def guess_payload_class(self, payload):
        return Padding

class MBusVIFe_List_Ext1(Packet):
    name = "MBus VIFE list EXT1"
    fields_desc = [
        PacketListField("VIFe", MBusVIFe_Ext1(), MBusVIFe_Ext1, count_from=lambda pkt: pkt.underlayer.get_nvifs())
    ]
    def guess_payload_class(self, payload):
        return Padding


######### VIFE Extended 2 #########
class MBusVIFe_Ext2(Packet):
    name = "MBus VIF2"
    fields_desc = [
        BitEnumField("extension", 0, 1, VIF_extension),
        BitEnumField("unit", "Reserved", 7, VIFe_ext2),
    ]

    def guess_payload_class(self, payload):
        return Padding


class MBusVIFe_List_Ext2(Packet):
    name = "MBus VIFE list EXT2"
    fields_desc = [
        PacketListField("VIFe", MBusVIFe_Ext2(), MBusVIFe_Ext2, count_from=lambda pkt: pkt.underlayer.get_nvifs()),
    ]





######### APPLICATION LAYER #########
class MBusDataRecordHeader(Packet):
    __slots__ = [ "data_len" ]
    name = "MBus DataRecord"
    fields_desc = [
        PacketField("DIF",MBusDIF(), MBusDIF),
        PacketField("VIF",MBusVIF(), MBusVIF)
    ]

    def get_ndifs(self):
        return self.ndifs

    def get_data_len(self):
        return self.data_len

    def pre_dissect(self, s): #Search for data len : (last DIF)
        self.data_len = 0;
        for i in s:
            if (ord(i) & 0x80 != 0x80): #Get last DIF
                self.data_len = (ord(i) & 0xF) 
                break
        return s

    def guess_payload_class(self, payload):
        if self.data_len == 1:
            return MBusValue_1
        if self.data_len == 2:
            return MBusValue_2
        if self.data_len == 3:
            return MBusValue_3
        if self.data_len == 4:
            return MBusValue_4
        if self.data_len == 5:
            return MBusValue_4
        if self.data_len == 6:
            return MBusValue_5
        if self.data_len == 7:
            return MBusValue_6
        if self.data_len >= 8:
            return MBusValue_7
        return Padding


class MBusData(Packet):
    name = "MBus Data"
    fields_desc = [
        PacketListField("data", MBusDataRecordHeader(), MBusDataRecordHeader)
    ]





######### DATA INTERPRETATION #########
class MBusValue(Packet):
    name = "MBus Value"

    def guess_payload_class(self, payload):
        return Padding


class MBusValue_1(MBusValue):
    fields_desc = [ ByteField("value", 0) ]

class MBusValue_2(MBusValue):
    fields_desc = [ LEShortField("value", 0) ]

class MBusValue_3(MBusValue):
    fields_desc = [ BitField("value", 3, 24) ]

class MBusValue_4(MBusValue):
    fields_desc = [ LEIntField("value", 4) ]

class MBusValue_5(MBusValue):
    fields_desc = [ BitField("value", 6, 48) ]

class MBusValue_6(MBusValue):
    fields_desc = [ LELongField("value", 7) ]

class MBusValue_7(MBusValue):
    fields_desc = [ StrFixedLenField("value", 8, length=8) ]