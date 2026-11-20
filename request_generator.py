import struct


class RequestGenerator:
    @staticmethod
    def generate_simple_dns_request(tid) -> bytes:
        # ! - биг эндиан H - 2 байта, собираем header
        # tid присылают, в флагах всё по нулям, вопросов 1, ответов 0, nscount 0, arcount 0
        header = tid + struct.pack('!HHHHH', 0, 1, 0, 0, 0)
        # спрашиваем о example.com  (B - 1 байт)
        qname = (struct.pack("!B", 7) + b"example"
                 + struct.pack("!B", 3) + b"com"
                 + struct.pack("!B", 0))
        # тип А и класс In
        qtype = struct.pack("!H", 1)
        qclass = struct.pack("!H", 1)
        return header + qname + qtype + qclass


    @staticmethod
    def generate_simple_http_request():
        return b"GET / HTTP/1.1\r\n\r\n"

    @staticmethod
    def generate_simple_echo_request():
        return b"Hello"