# -*- coding: utf-8 -*-
## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus Defence and Space
## Authors: Jean-Michel Huguet, Adam Reziouk, Jonathan-Christofer Demay
## This program is published under a GPLv2 license


"""
M-Bus Enums File.
Inspired from:
   http://www.m-bus.com/files/w4b21021.pdf
   https://github.com/CBrunsch/scambus
"""


############## MBusShortHeader
SH_error_code = {
    0: "No error",
    1: "Application busy",
    2: "Any application error",
    3: "Abnormal condition/alarm"
}
SH_access = {
    0: "No access",
    1: "Temporary no access",
    2: "Limited access",
    3: "Unlimited access"
}
SH_encryption = {
    0: "Clear Text",
    1: "Reserved 1",
    2: "DES-CBC, null IV",
    3: "DES-CBC, non-null IV",
    4: "AES128-CBC, null IV",
    5: "AES128-CBC, non-null IV",
    6: "Reserved for new encryption"
}



############## MBusLinkLayer
LL_function_codes = {
    0x0: 'SND-NKE',
    0x3: 'SND-UD',
    0x4: 'SND-NR',
    0x6: 'SND-IR',
    0x7: 'ACC-NR',
    0x8: 'ACC-DMD',
    0xA: 'REQ-UD1',
    0xB: 'REQ-UD2'
}

LL_device_types = {
    0x00: 'Other',
    0x01: 'Oil',
    0x02: 'Electricity',
    0x03: 'Gas',
    0x04: 'Head',
    0x05: 'Steam ',
    0x06: 'Warm water (30-90 °C)',
    0x07: 'Water ',
    0x08: 'Heat cost allocator ',
    0x09: 'Compressed air ',
    0x0A: 'Cooling load meter (Volume measured at return temperature: outlet)',
    0x0B: 'Cooling load meter (Volume measured at flow temperature: inlet)',
    0x0C: 'Heat (Volume measured at flow temperature: inlet)',
    0x0D: 'Heat / Cooling load meter',
    0x0E: 'Bus / System component',
    0x0F: 'Unknown medium',
    0x10: 'Reserved for consumption meter',
    0x11: 'Reserved for consumption meter',
    0x12: 'Reserved for consumption meter',
    0x13: 'Reserved for consumption meter',
    0x14: 'Calorific value',
    0x15: 'Hot water (≥ 90 °C)',
    0x16: 'Cold water',
    0x17: 'Dual register (hot/cold) water meter',
    0x18: 'Pressure',
    0x19: 'A/D Converter',
    0x1A: 'Smoke detector',
    0x1B: 'Room sensor (eg temperature or humidity)',
    0x1C: 'Gas detector',
    0x1D: 'Reserved for sensors',
    0x1F: 'Reserved for sensors',
    0x20: 'Breaker (electricity)',
    0x21: 'Valve (gas or water)',
    0x22: 'Reserved for switching devices',
    0x23: 'Reserved for switching devices',
    0x24: 'Reserved for switching devices',
    0x25: 'Customer unit (display device)',
    0x26: 'Reserved for customer units',
    0x27: 'Reserved for customer units',
    0x28: 'Waste water',
    0x29: 'Garbage',
    0x2A: 'Reserved for Carbon dioxide',
    0x2B: 'Reserved for environmental meter',
    0x2C: 'Reserved for environmental meter',
    0x2D: 'Reserved for environmental meter',
    0x2E: 'Reserved for environmental meter',
    0x2F: 'Reserved for environmental meter',
    0x30: 'Reserved for system devices',
    0x31: 'Reserved for communication controller',
    0x32: 'Reserved for unidirectional repeater',
    0x33: 'Reserved for bidirectional repeater',
    0x34: 'Reserved for system devices',
    0x35: 'Reserved for system devices',
    0x36: 'Radio converter (system side)',
    0x37: 'Radio converter (meter side)',
    0x38: 'Reserved for system devices',
    0x39: 'Reserved for system devices',
    0x3A: 'Reserved for system devices',
    0x3B: 'Reserved for system devices',
    0x3C: 'Reserved for system devices',
    0x3D: 'Reserved for system devices',
    0x3E: 'Reserved for system devices',
    0x3F: 'Reserved for system devices'
}

LL_control_information = {
    0x60: 'COSEM Data sent by the Readout device to the meter with long Transport Layer',
    0x61: 'COSEM Data sent by the Readout device to the meter with short Transport Layer',
    0x64: 'Reserved for OBIS-based Data sent by the Readout device to the meter with long Transport Layer',
    0x65: 'Reserved for OBIS-based Data sent by the Readout device to the meter with short Transport Layer',
    0x69: 'EN 13757-3 Application Layer with Format frame and no Transport Layer',
    0x6A: 'EN 13757-3 Application Layer with Format frame and with short Transport Layer',
    0x6B: 'EN 13757-3 Application Layer with Format frame and with long Transport Layer',
    0x6C: 'Clock synchronisation (absolute)',
    0x6D: 'Clock synchronisation (relative)',
    0x6E: 'Application error from device with short Transport Layer',
    0x6F: 'Application error from device with long Transport Layer',
    0x70: 'Application error from device without Transport Layer',
    0x71: 'Reserved for Alarm Report',
    0x72: 'EN 13757-3 Application Layer with long Transport Layer',
    0x73: 'EN 13757-3 Application Layer with Compact frame and long Transport Layer',
    0x74: 'Alarm from device with short Transport Layer',
    0x75: 'Alarm from device with long Transport Layer',
    0x78: 'EN 13757-3 Application Layer without Transport Layer (to be defined)',
    0x79: 'EN 13757-3 Application Layer with Compact frame and no header',
    0x7A: 'EN 13757-3 Application Layer with short Transport Layer',
    0x7B: 'EN 13757-3 Application Layer with Compact frame and short header',
    0x7C: 'COSEM Application Layer with long Transport Layer',
    0x7D: 'COSEM Application Layer with short Transport Layer',
    0x7E: 'Reserved for OBIS-based Application Layer with long Transport Layer',
    0x7F: 'Reserved for OBIS-based Application Layer with short Transport Layer',
    0x80: 'EN 13757-3 Transport Layer (long) from other device to the meter',
    0x81: 'Network Layer data',
    0x82: 'For future use',
    0x83: 'Network Management application',
    0x8A: 'EN 13757-3 Transport Layer (short) from the meter to the other device',
    0x8B: 'EN 13757-3 Transport Layer (long) from the meter to the other device',
    0x8C: 'Extended Link Layer I (2 Byte)',
    0x8D: 'Extended Link Layer II (8 Byte)'
}



############## MBusDIF
DIF_extension = {
    0x0: 'Last DIF',
    0x1: 'Other DIFs are following',
}

DIF_function = {
    0x0: 'Instantaneous value',
    0x1: 'Maximum value',
    0x2: 'Minimum value',
    0x3: 'Value during error state'
}

DIF_data_info = {
    0x0: 'No data',
    0x1: '8 Bit Integer',
    0x2: '16 Bit Integer',
    0x3: '24 Bit Integer',
    0x4: '32 Bit Integer',
    0x5: '32 Bit Real',
    0x6: '48 Bit Integer',
    0x7: '64 Bit Integer',
    0x8: 'Selection for Readout',
    0x9: '2 digit BCD',
    0xA: '4 digit BCD',
    0xB: '6 digit BCD',
    0xC: '8 digit BCD',
    0xD: 'Variable length',
    0xE: '12 digit BCD',
    0xF: 'Special Functions'
}


############## WMBusDIFE
DIFE_unit = {
    0x0: 'Reactive',
    0x1: 'Apparent'
}

DIFE_tariff = {
    0x0: 'Total Value',
    0x1: 'Tariff 1',
    0x2: 'Tariff 2',
    0x3: 'Tariff 1 + 2'
}





############## MBusVIF
VIF_extension = {
    0x0: 'Last VIF',
    0x1: 'Other VIFs are following'
}


#Main extension VIF
VIF_Main = {
    0x00: 'Energy mWh',
    0x01: 'Energy 10⁻² Wh',
    0x02: 'Energy 10⁻¹ Wh',
    0x03: 'Energy Wh',
    0x04: 'Energy 10¹ Wh',
    0x05: 'Energy 10² Wh',
    0x06: 'Energy kWh',
    0x07: 'Energy 10⁴ Wh',

    0x08: 'Energy J',
    0x09: 'Energy 10¹ J',
    0x0A: 'Energy 10² J',
    0x0B: 'Energy kJ',
    0x0C: 'Energy 10⁴ J',
    0x0D: 'Energy 10⁵ J',
    0x0E: 'Energy MJ',
    0x0F: 'Energy 10⁷ J',
    
    0x10: 'Volume cm³',
    0x11: 'Volume 10⁻⁵ m³',
    0x12: 'Volume 10⁻⁴ m³',
    0x13: 'Volume l',
    0x14: 'Volume 10⁻² m³',
    0x15: 'Volume 10⁻¹ m³',
    0x16: 'Volume m³',
    0x17: 'Volume 10¹ m³',

    0x18: 'Mass g',
    0x19: 'Mass 10⁻² kg',
    0x1A: 'Mass 10⁻¹ kg',
    0x1B: 'Mass kg',
    0x1C: 'Mass 10¹ kg',
    0x1D: 'Mass 10² kg',
    0x1E: 'Mass t',
    0x1F: 'Mass 10⁴ kg',
    
    0x20: 'On time seconds',
    0x21: 'On time minutes',
    0x22: 'On time hours',
    0x23: 'On time days',

    0x24: 'Operating time seconds',
    0x25: 'Operating time minutes',
    0x26: 'Operating time hours',
    0x27: 'Operating time days',

    0x28: 'Power mW',
    0x29: 'Power 10⁻² W',
    0x2A: 'Power 10⁻¹ W',
    0x2B: 'Power W',
    0x2C: 'Power 10¹ W',
    0x2D: 'Power 10² W',
    0x2E: 'Power kW',
    0x2F: 'Power 10⁴ W',
    
    0x30: 'Power J/h',
    0x31: 'Power 10¹ J/h',
    0x32: 'Power 10² J/h',
    0x33: 'Power kJ/h',
    0x34: 'Power 10⁴ J/h',
    0x35: 'Power 10⁵ J/h',
    0x36: 'Power MJ/h',
    0x37: 'Power 10⁷ J/h',

    0x38: 'Volume flow cm³/h',
    0x39: 'Volume flow 10⁻⁵ m³/h',
    0x3A: 'Volume flow 10⁻⁴ m³/h',
    0x3B: 'Volume flow l/h',
    0x3C: 'Volume flow 10⁻² m³/h',
    0x3D: 'Volume flow 10⁻¹ m³/h',
    0x3E: 'Volume flow m³/h',
    0x3F: 'Volume flow 10¹ m³/h',
    
    0x40: 'Volume flow ext. 10⁻⁷ m³/min',
    0x41: 'Volume flow ext. cm³/min',
    0x42: 'Volume flow ext. 10⁻⁵ m³/min',
    0x43: 'Volume flow ext. 10⁻⁴ m³/min',
    0x44: 'Volume flow ext. l/min',
    0x45: 'Volume flow ext. 10⁻² m³/min',
    0x46: 'Volume flow ext. 10⁻¹ m³/min',
    0x47: 'Volume flow ext. m³/min',
    0x48: 'Volume flow ext. mm³/s',
    0x49: 'Volume flow ext. 10⁻⁸ m³/s',
    0x4A: 'Volume flow ext. 10⁻⁷ m³/s',
    0x4B: 'Volume flow ext. cm³/s',
    0x4C: 'Volume flow ext. 10⁻⁵ m³/s',
    0x4D: 'Volume flow ext. 10⁻⁴ m³/s',
    0x4E: 'Volume flow ext. l/s',
    0x4F: 'Volume flow ext. 10⁻² m³/s',
    
    0x50: 'Mass g/h',
    0x51: 'Mass 10⁻² kg/h',
    0x52: 'Mass 10⁻¹ kg/h',
    0x53: 'Mass kg/h',
    0x54: 'Mass 10¹ kg/h',
    0x55: 'Mass 10² kg/h',
    0x56: 'Mass t/h',
    0x57: 'Mass 10⁴ kg/h',

    0x58: 'Flow temperature 10⁻³ °C',
    0x59: 'Flow temperature 10⁻² °C',
    0x5A: 'Flow temperature 10⁻¹ °C',
    0x5B: 'Flow temperature °C',

    0x5C: 'Return temperature 10⁻³ °C',
    0x5D: 'Return temperature 10⁻² °C',
    0x5E: 'Return temperature 10⁻¹ °C',
    0x5F: 'Return temperature °C',
    
    0x60: 'Temperature difference mK',
    0x61: 'Temperature difference 10⁻² K',
    0x62: 'Temperature difference 10⁻¹ K',
    0x63: 'Temperature difference K',

    0x64: 'External temperature 10⁻³ °C',
    0x65: 'External temperature 10⁻² °C',
    0x66: 'External temperature 10⁻¹ °C',
    0x67: 'External temperature °C',

    0x68: 'Pressure mbar',
    0x69: 'Pressure 10⁻² bar',
    0x6A: 'Pressure 10⁻1 bar',
    0x6B: 'Pressure bar',

    0x6C: 'Date type G',       # (date) actual or associated with a storage number/function
    0x6D: 'Date type F',       # (time & date) 
    0x6E: 'Units for H.C.A.',  # dimensionless
    0x6F: 'Reserved',          # for a future third table of VIF-extensions
    
    0x70: 'Averaging duration seconds',
    0x71: 'Averaging duration minutes',
    0x72: 'Averaging duration hours',
    0x73: 'Averaging duration days',

    0x74: 'Actuality duration seconds',
    0x75: 'Actuality duration minutes',
    0x76: 'Actuality duration hours',
    0x77: 'Actuality duration days',

    0x78: 'Fabrication no',
    0x79: 'Enhanced identification',    #See apendix E2
    0x7A: 'Bus Address',                #Data type C (x=8)
    0x7B: 'First Extension of VIF-codes',     #Next vife is in Table 10
    0x7C: 'VIF in following string (length in first byte)',  # Allows user definable VIF s (in plain ASCII-String)
    0x7D: 'Second Extension of VIF-codes',     #Next vife is in Table 11
    0x7E: 'Any VIF',                                         # Used for readout selection of all VIF s (see chapter 9.2)
    0x7F: 'Manufacturer specific',                            # VIFE s and data of this block are manufacturer specific

}


#VIF First Extension
VIFe_ext1 = {
    0x00: '+10⁻³ of the nominal local legal currency unit',
    0x01: '+10⁻² of the nominal local legal currency unit',
    0x02: '+10⁻¹ of the nominal local legal currency unit',
    0x03: '+1 of the nominal local legal currency unit',

    0x04: '-10⁻³ of the nominal local legal currency unit',
    0x05: '-10⁻² of the nominal local legal currency unit',
    0x06: '-10⁻¹ of the nominal local legal currency unit',
    0x07: '-1 of the nominal local legal currency unit',

    0x08: 'Unique telegram identification (Tx Count)',
    0x09: 'Device type',
    0x0A: 'Manufacturer',
    0x0B: 'Parameter set identification',
    0x0C: 'Model / Version',
    0x0D: 'Hardware version number',
    0x0E: 'Firmware version number',
    0x0F: 'Other software version number',
    0x10: 'Customer location',
    0x11: 'Customer',

    0x12: 'Access code user',
    0x13: 'Access code operator',
    0x14: 'Access code system operator',
    0x15: 'Access code developer',

    0x16: 'Password',
    0x17: 'Error flags (binary) (device type specific)',
    0x18: 'Error mask',
    0x19: 'Reserved',
    0x1A: 'Digital output (binary)',
    0x1B: 'Digital Input (binary)',
    0x1C: 'Baud rate [baud]',
    0x1D: 'Response delay time [bit-times]',
    0x1E: 'Retry',
    0x1F: 'Remote control',
    0x20: 'First storage number for cyclic storage',
    0x21: 'Last storage number for cyclic storage',
    0x22: 'Size of storage block',
    0x23: 'Reserved',

    0x24: 'Storage interval (seconds)',
    0x25: 'Storage interval (minutes)',
    0x26: 'Storage interval (hours)',
    0x27: 'Storage interval (days)',
    0x28: 'Storage interval (months)',
    0x29: 'Storage interval (years)',

    0x2A: 'Operator specific data',
    0x2B: 'Time point second (0 to 59)',

    0x2C: 'Seconds since last readout ',
    0x2D: 'Minutes since last readout ',
    0x2E: 'Hours since last readout ',
    0x2F: 'Days since last readout ',

    0x30: 'Start (date/time) of tariff',

    0x31: 'Duration of tariff (minutes)',
    0x32: 'Duration of tariff (hours)',
    0x33: 'Duration of tariff (days)',

    0x34: 'Period of tariff (seconds)',
    0x35: 'Period of tariff (minutes)',
    0x36: 'Period of tariff (hours)',
    0x37: 'Period of tariff (days)',
    0x38: 'Period of tariff (months)',
    0x39: 'Period of tariff (years)',

    0x3A: 'Dimensionless / no VIF',
    0x3B: 'Data container for wireless M-Bus protocol',

    0x3C: 'Period of nominal data transmissions (seconds)',
    0x3D: 'Period of nominal data transmissions (minutes)',
    0x3E: 'Period of nominal data transmissions (hours)',
    0x3F: 'Period of nominal data transmissions (days)',


    0x40: 'Voltage nV',
    0x41: 'Voltage 10⁻⁸ V',
    0x42: 'Voltage 10⁻⁷ V',
    0x43: 'Voltage μV',
    0x44: 'Voltage 10⁻⁵ V',
    0x45: 'Voltage 10⁻⁴ V',
    0x46: 'Voltage mV',
    0x47: 'Voltage 10⁻² V',
    0x48: 'Voltage 10⁻¹ V',
    0x49: 'Voltage V',
    0x4A: 'Voltage 10 V',
    0x4B: 'Voltage 10² V',
    0x4C: 'Voltage kV',
    0x4D: 'Voltage 10 kV',
    0x4E: 'Voltage 10² kV',
    0x4F: 'Voltage MV',


    0x50: 'Current pA',
    0x51: 'Current 10⁻¹¹ A',
    0x52: 'Current 10⁻¹⁰ A',
    0x53: 'Current nA',
    0x54: 'Current 10⁻⁸ A',
    0x55: 'Current 10⁻⁷ A',
    0x56: 'Current μA',
    0x57: 'Current 10⁻⁵ A',
    0x58: 'Current 10⁻⁴ A',
    0x59: 'Current mA',
    0x5A: 'Current 10⁻² A',
    0x5B: 'Current 10⁻¹ A',
    0x5C: 'Current A',
    0x5D: 'Current 10 A',
    0x5E: 'Current 10² A',
    0x5F: 'Current kA',

    0x60: 'Reset counter',
    0x61: 'Cumulation counter',
    0x62: 'Control signal',
    0x63: 'Day of week',
    0x64: 'Week number',
    0x65: 'Time point of day change',
    0x66: 'State of parameter activation',
    0x67: 'Special supplier information',

    0x68: 'Hours since last cumulation',
    0x69: 'Days since last cumulation',
    0x6A: 'Months since last cumulation',
    0x6B: 'Years since last cumulation',

    0x6C: 'Battery Operating time (hours)',
    0x6D: 'Battery Operating time (days)',
    0x6E: 'Battery Operating time (months)',
    0x6F: 'Battery Operating time (years)',

    0x70: 'Date and time of battery change',
    0x71: 'RF level units: dBm',
    0x72: 'Day light saving (beginning, ending, deviation)',
    0x73: 'Listening window management',
    0x74: 'Remaining battery life time (days)',
    0x75: 'Number times the meter was stopped',
    0x76: 'Data container for manufacture specific protocol',

#0x77 - 0x7F: "reserved"
}

#VIF Second Extension
VIFe_ext2 = {
    0x00: 'Energy 10⁻¹ MWh',
    0x01: 'Energy MWh',
    0x02: 'Reactive energy kVARh',
    0x03: 'Reactive energy 10 kVARh',

    #0x04 - 0x07: "reserved"

    0x08: 'Energy 10⁻¹ GJ',
    0x09: 'Energy GJ',

    #0x0A - 0x0B: "reserved"

    0x0C: 'Energy 10⁻¹ MCal',
    0x0D: 'Energy MCal',
    0x0E: 'Energy 10 MCal',
    0x0F: 'Energy 10² MCal',
    0x10: 'Volume 10² m³',
    0x11: 'Volume 10³ m³',

    #0x12 - 0x13: "reserved"

    0x14: 'Reactive power 10⁻³ kVAR',
    0x15: 'Reactive power 10⁻² kVAR',
    0x16: 'Reactive power 10⁻¹ kVAR',
    0x17: 'Reactive power 1 kVAR',
    0x18: 'Mass 10² t',
    0x19: 'Mass 10³ t',
    0x1A: 'Relative humidity 0.1%',
    0x1B: 'Relative humidity 1%',

    #0x1C - 0x1F: "reserved"

    0x20: 'Volume feet³',
    0x21: 'Volume 10⁻¹ feet³',
    0x22: 'Volume 10⁻¹ USgallon',
    0x23: 'Volume USgallon',
    0x24: 'Volume 10³ Usgallon/min',
    0x25: 'Volume 1 USgallon/min',
    0x26: 'Volume 1 USgallon/h',
    0x27: 'Reserved',
    0x28: 'Power 10⁻¹ MW',
    0x29: 'Power MW',
    0x2A: 'Phase U-U (volt. to volt.) 0.1',
    0x2B: 'Phase U-I (volt. to current) 0.1',
    0x2C: 'Frequency 10⁻³ Hz',
    0x2D: 'Frequency 10⁻² Hz',
    0x2E: 'Frequency 10⁻¹ Hz',
    0x2F: 'Frequency Hz',
    0x30: 'Power 10⁻¹ GJ/h',
    0x31: 'Power GJ/h',

    #0x32 - 0x57: "reserved"

    0x58: 'Flow temperature 10⁻³ °F',
    0x59: 'Flow temperature 10⁻² °F',
    0x5A: 'Flow temperature 10⁻¹ °F',
    0x5B: 'Flow temperature °F',
    0x5C: 'Return temperature 10⁻³ °F',
    0x5D: 'Return temperature 10⁻² °F',
    0x5E: 'Return temperature 10⁻¹ °F',
    0x5F: 'Return temperature °F',
    0x60: 'Temperature differ 10⁻³ °F',
    0x61: 'Temperature differ 10⁻² °F',
    0x62: 'Temperature differ 10⁻¹ °F',
    0x63: 'Temperature differ °F',
    0x64: 'Flow temperature 10⁻³ °F', #Same as 0x58 - 0x5B
    0x65: 'Flow temperature 10⁻² °F',
    0x66: 'Flow temperature 10⁻¹ °F',
    0x67: 'Flow temperature °F',

    #0x68 - 0x6F: "reserved"

    0x70: 'Cold/Warm Temp. Lim. 10⁻³ °F',
    0x71: 'Cold/Warm Temp. Lim. 10⁻² °F',
    0x72: 'Cold/Warm Temp. Lim. 10⁻¹ °F',
    0x73: 'Cold/Warm Temp. Lim. °F',

    0x74: 'Cold/Warm Temp. Lim. 10⁻³ °C',
    0x75: 'Cold/Warm Temp. Lim. 10⁻² °C',
    0x76: 'Cold/Warm Temp. Lim. 10⁻¹ °C',
    0x77: 'Cold/Warm Temp. Lim. °C',

    0x78: 'Cum. Count Max.power mW',
    0x79: 'Cum. Count Max.power 10⁻² W',
    0x7A: 'Cum. Count Max.power 10⁻¹ W',
    0x7B: 'Cum. Count Max.power W',
    0x7C: 'Cum. Count Max.power 10 W',
    0x7D: 'Cum. Count Max.power 10² W',
    0x7E: 'Cum. Count Max.power kW',
    0x7F: 'Cum. Count Max.power 10 kW'

}
