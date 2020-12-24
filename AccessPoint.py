from jsonpickle import encode
'''
    Maintains and updates key information pertaining to an Access Point
'''
class AccessPoint:

    '''
        Constructor for the Filter class.
        @param dBm: Output power level of a given access point.
        @param ssid: Human readable name given to a Wi-Fi network.
        @param MAC: Source MAC address from a recorded packet.
    '''
    def __init__(self, dBm, MAC, ssid):
        self.dBm = dBm
        self.MAC = MAC
        self.ssid = ssid
        self.clients = [] # Tuple containing (Client, current time)

    '''
        Convert instance of class to a JSON object 
        to be sent over a socket / serialization.
    '''
    def toJSON(self):
        return encode(self)



