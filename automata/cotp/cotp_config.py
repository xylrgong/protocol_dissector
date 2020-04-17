

class COTP_Connection(object):
    def __init__(self, dmac='00:00:00:00:00:00', smac='00:00:00:00:00:00', dref=0x00, sref=0x00):
        self.dmac = dmac,
        self.smac = smac,
        self.dref = dref,
        self.sref = sref

    def __eq__(self, other):
        return self.dmac == other.dmac and \
                self.smac == other.smac and \
                self.dref == other.dref and \
                self.sref == other.sref


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
