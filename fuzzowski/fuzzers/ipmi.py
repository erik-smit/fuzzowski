from fuzzowski import *
from fuzzowski.fuzzers import IFuzzer


class IPMIFuzzer(IFuzzer):
    name = 'ipmi_fuzzer'  # This is how the fuzzer is named in the 
                             # Fuzzowski Arguments, with the -f option

    @staticmethod
    def get_requests() -> List[callable]:
        """Get possible requests, returns a list of all the 
           callables which connects the paths to the session
        """
        return [IPMIFuzzer.rmcp_ping]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        """This method define all the possible requests, 
        it is called when loading a fuzzer
        """
        s_initialize('rmcp_ping')
        s_static(b'\x06', name='version')
        s_static(b'\x00', name='reserved1')
        s_static(b'\xff', name='sequence_number')
        s_static(b'\x06', name='class_of_message')
        s_static(b'\x00\x00', name='unknown')
        s_static(b'\x11\xbe', name='iana_number')
        s_static(b'\x80', name='message_type')
        s_static(b'\x00', name='message_tag')
        s_static(b'\x00', name='reserved2')
        s_static(b'\x00', name='data_length')
        s_delim(b'\x00')

    # ================================================================#
    # Callable methods to connect our requests to the session         #
    # ================================================================#

    @staticmethod
    def rmcp_ping(session: Session) -> None:
        session.connect(s_get('rmcp_ping'))


# Sending IPMI/RMCP presence ping packet
# send_packet (12 bytes)
#  06 00 ff 06 00 00 11 be 80 00 00 00
# recv_packet (28 bytes)
#  06 00 ff 06 00 00 11 be 40 00 00 10 00 00 11 be
#  00 00 00 00 81 00 00 00 00 00 00 00

# echo 0600 ff06 0000 11be 8000 0000 | xxd -r -ps | socat - udp-datagram:localhost:6234 | xxd
# 00000000: 0600 ff06 0000 11be 4000 0010 0000 11be  ........@.......
# 00000010: 0000 0000 8100 0000 0000 0000            ............