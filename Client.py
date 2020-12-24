from jsonpickle import encode

'''
    Maintains and updates key information for an individual client
    that is associated with a Wi-Fi network.
'''
class Client:

    '''
        Constructor for the Client class.
        @param MAC: MAC address of a client on a network.
        @param pwr: Output power of the client.
        @param uTime: Time of client detection (datetime object)
    '''
    def __init__(self, MAC, pwr, uTime):
        self.MAC = MAC
        self.pwr = pwr
        self.uTime = uTime
        self.contacts = [] # MAC addrs that client sent data to

    '''
        Convert instance of class to a JSON object 
        to be sent over a socket / serialization.
    '''
    def toJSON(self):
        return encode(self)
