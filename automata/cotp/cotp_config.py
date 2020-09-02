

COTP_TIMEOUT = 15  # 单位： 秒

COTP_ERR_CODE = {
    100: 'Invalid dst mac',
    101: 'Invalid src mac',
    102: 'Invalid dst ref',
    103: 'Invalid src ref',
    200: 'Timeout',
    201: 'Connection closed'
}


class COTP_Params(object):
    def __init__(self):
        self.iface = ''
        self.is_passive = False
        self.conn = None
        self.your_tpdunr = 0
        self.my_tpdunr = 0
        self.credit = 0
        self.cause = 0


class COTP_Connection(object):
    def __init__(self, dmac='00:00:00:00:00:00', smac='00:00:00:00:00:00', dref=0x00, sref=0x00):
        self.dmac = dmac
        self.smac = smac
        self.dref = dref
        self.sref = sref

    # per flow hash value
    def get_hash(self):
        return abs(hash((self.dmac, self.smac)) +
                   hash((self.smac, self.dmac)))

    def __eq__(self, other):
        return self.dmac == other.dmac and \
               self.smac == other.smac and \
               self.sref == other.sref and \
               self.dref == other.dref

    def __str__(self):
        return '[COTP CONNECTION] dmac:({}) smac:({}) dref:({}) sref:({})'.format(self.dmac, self.smac, self.dref, self.sref)


class COTP_Config(object):
    connections = []

    @staticmethod
    def add_conn(conn):
        assert isinstance(conn, COTP_Connection)
        if conn not in COTP_Config.connections:
            COTP_Config.connections.append(conn)

    @staticmethod
    def pop_conn(conn):
        try:
            i = COTP_Config.connections.index(conn)
            return COTP_Config.connections.pop(i)
        finally:
            return None

    @staticmethod
    def has_conn(conn):
        return conn in COTP_Config.connections

cotp_conf = COTP_Config()
