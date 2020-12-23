from binascii import hexlify

'''
    Transforms captured packets into a readable form.
'''
class Filter:

    '''
        Returns the MAC address of an access point
    '''
    @staticmethod
    def getAPMAC(packet):
        return hexlify(packet[40:46]).decode()

    '''
        Returns the MAC address of a client
    '''

    @staticmethod
    def getCLIMAC(packet):
        MAC = '***'
        control_fields = ['b4']
        subtype = hexlify(packet[36:37]).decode()

        if subtype in control_fields:
            MAC = '***'

        else:
            MAC = hexlify(packet[46:51]).decode()

        return MAC

    '''
        Returns the network SSID
    '''

    @staticmethod
    def getSSID(packet):
        SSID = ''
        subtype = hexlify(packet[36:37]).decode()

        if subtype in control_fields:
            SSID = '***'

        return SSID
