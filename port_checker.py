import socket
import time
import os
import select
import random
import struct
import sys
from request_generator import RequestGenerator


class PortChecker:
    @staticmethod
    def scan_udp_ports(address, ports, timeout, is_guess):
        result = []
        if not ports:
            return result

        # получаем ip хоста
        target_ip = socket.gethostbyname(address)

        # максимум 1000 сокета, добавляем 25 сокетов в 5 мс
        max_active = 1000
        add_batch = 25
        add_delay = 0.005

        # генерируем 2 байтовый айди для днс и запросы для проверки протоколов
        tid = os.urandom(2)
        dns_req = RequestGenerator.generate_simple_dns_request(tid)
        echo_req = RequestGenerator.generate_simple_echo_request()
        http_req = RequestGenerator.generate_simple_http_request()
        payloads = (dns_req, echo_req, http_req) if is_guess else (b"\r\n",)
        echo_payloads = {dns_req, echo_req, http_req}

        active_sockets = {}
        port_idx = 0
        total_ports = len(ports)

        try:
            # пока есть что добавлять или есть активные сокеты
            while port_idx < total_ports or active_sockets:
                # добавляем порты в свободные места
                if port_idx < total_ports and len(active_sockets) < max_active:
                    to_add = min(add_batch, max_active - len(active_sockets), total_ports - port_idx)
                    for _ in range(to_add):
                        port = ports[port_idx]
                        port_idx += 1
                        s = None
                        # создаём для порта сокет
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            s.setblocking(False)
                            # коннект позволяет отлавливать ICMP Port Unreachable как исключение
                            s.connect((target_ip, port))
                            now = time.time()
                            closed = False
                            # отправляем сразу все необходимые пакеты
                            for payload in payloads:
                                try:
                                    s.send(payload)
                                except (ConnectionRefusedError, ConnectionResetError):
                                    # порт закрыт
                                    result.append((port, False, "-", 0))
                                    closed = True
                                    break
                                except OSError:
                                    pass
                            if closed:
                                s.close()
                            else:
                                active_sockets[s] = {
                                    "port": port,
                                    "start": now,
                                    "deadline": now + timeout,
                                    "responded": False,
                                    "elapsed_ms": int(timeout * 1000),
                                }
                        except Exception:
                            if s:
                                s.close()
                            result.append((port, False, "-", 0))
                if not active_sockets:
                    continue

                # ждём фикс время и проверяем, пришли ли ответы от каких-то сокетов
                sock_list = list(active_sockets)
                ready, _, errors = select.select(sock_list, [], sock_list, add_delay)
                now = time.time()
                for s in set(ready + errors):
                    info = active_sockets.get(s)
                    if not info:
                        continue
                    port = info["port"]
                    elapsed_ms = int((now - info["start"]) * 1000)
                    done = False

                    while True:
                        try:
                            data = s.recv(1024)
                        except BlockingIOError:
                            break
                        except (ConnectionRefusedError, ConnectionResetError):
                            result.append((port, False, "-", 0))
                            done = True
                            break
                        except Exception:
                            done = True
                            break

                        if not data:
                            break

                        if is_guess:
                            # флаг ответа стоит и tid совпадает => DNS
                            if len(data) >= 3 and data[:2] == tid and (data[2] & 0x80):
                                result.append((port, True, "DNS", elapsed_ms))
                                done = True
                                break
                            # начинается в HTTP => http
                            elif data.startswith(b"HTTP"):
                                result.append((port, True, "HTTP", elapsed_ms))
                                done = True
                                break
                            # повторил наш запрос => echo
                            elif data in echo_payloads:
                                result.append((port, True, "ECHO", elapsed_ms))
                                done = True
                                break
                            # пришёл непонятный ответ запоминаем его время, но ждём ответы на остальные 2 запроса
                            elif not info["responded"]:
                                info["responded"] = True
                                info["elapsed_ms"] = elapsed_ms
                        # без режима угадывания просто говорим, что открыты
                        else:
                            result.append((port, True, "-", elapsed_ms))
                            done = True
                            break
                    if done:
                        active_sockets.pop(s, None)
                        s.close()
                # все порты с таймаутом считаем открытыми, просто не слушаются
                now = time.time()
                while active_sockets:
                    # первый самый старый, если он ещё свежий, то все остальные тоже
                    first_sock, first_info = next(iter(active_sockets.items()))
                    if now < first_info["deadline"]:
                        break
                    active_sockets.pop(first_sock)
                    first_sock.close()
                    result.append((first_info["port"], True, "-", first_info["elapsed_ms"]))
        finally:
            for s in active_sockets:
                s.close()

        return result
    @staticmethod
    def calculate_checksum(data):
        # если длина нечётная, докидываем нулевой байт в конец
        if len(data) % 2 != 0:
            data += b'\x00'

        total = 0
        for i in range(0, len(data), 2):
            # собираем 16битное число в биг эндиан, старший байт сдвигаем на 8 бит
            word = (data[i] << 8) + data[i + 1]
            total += word

        # срезаем, пока число не влезет в 16 бит
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)

        # Побитовое отрицание
        return ~total & 0xFFFF

    @staticmethod
    def build_tcp_packet(source_ip, target_ip, source_port, dest_port, flags=0x02, seq=None):
        if seq is None:
            seq = random.randint(0, 0xFFFFFFFF)  # рандомный начальный номер байта
        ack_seq = 0  # нет подтверждённых байт
        offset_res = (5 << 4)  # 20 байт длина заголовка
        window = 65535
        checksum = 0
        urg_ptr = 0  # срочных данных нет

        tcp_header = struct.pack(
            "!HHLLBBHHH",
            source_port, dest_port, seq, ack_seq,
            offset_res, flags, window, checksum, urg_ptr
        )
        # псевдохедер для подсчёта контрольной суммы (защищает от ошибок маршрутизации)
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(source_ip),
            socket.inet_aton(target_ip),
            0,
            socket.IPPROTO_TCP,
            len(tcp_header)
        )

        checksum = PortChecker.calculate_checksum(pseudo_header + tcp_header)

        return struct.pack(
            "!HHLLBBHHH",
            source_port, dest_port, seq, ack_seq,
            offset_res, flags, window, checksum, urg_ptr
        )

    @staticmethod
    def parse_tcp_packet(raw_data):
        if len(raw_data) < 20:
            return None

        # Вытаскиваем длину ip-заголовка из младших 4 бит первого байта
        ihl = (raw_data[0] & 0x0F) * 4

        # проверяем, что после ip-заголовка помещается хотя бы минимальный tcp (20 байт)
        if len(raw_data) < ihl + 20:
            return None

        # нужны только первые 14 байт tcp (порты, seq, ack, offset, flags)
        tcp_part = raw_data[ihl:ihl + 14]
        src_port, dst_port, _, ack_num, _, flags = struct.unpack("!HHLLBB", tcp_part)
        return src_port, dst_port, ack_num, flags

    @staticmethod
    def guess_tcp_protocol(target_ip, port, timeout):
        try:
            with socket.create_connection((target_ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                http_req = RequestGenerator.generate_simple_http_request()
                s.sendall(http_req)
                resp = s.recv(1024)
                if resp.startswith(b"HTTP"):
                    return "HTTP"
                if resp == http_req:
                    return "ECHO"
        except Exception:
            pass

        try:
            with socket.create_connection((target_ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                tid = struct.pack("!H", random.randint(0, 65535))
                dns_req = RequestGenerator.generate_simple_dns_request(tid)
                s.sendall(struct.pack("!H", len(dns_req)) + dns_req)
                resp = s.recv(1024)
                # resp[0:2] - длина ответа, resp[2:4] - наш tid, resp[4] & 0x80 - флаг ответа (QR=1)
                if len(resp) >= 6 and resp[2:4] == tid and (resp[4] & 0x80):
                    return "DNS"
        except Exception:
            pass

        try:
            with socket.create_connection((target_ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                echo_req = RequestGenerator.generate_simple_echo_request()
                s.sendall(echo_req)
                resp = s.recv(1024)
                if resp == echo_req:
                    return "ECHO"
        except Exception:
            pass

        return "-"

    @staticmethod
    def get_local_ip(target_ip):
        # создаём udp сокет и получаем локальный ip устройства, которое отправляет трафик
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, 80))
            return s.getsockname()[0]

    @staticmethod
    def scan_tcp_ports(address, ports, timeout, is_guess):
        result = []
        if not ports:
            return result

        # получаем реальный ip-адрес хоста и локальный адрес устройства, которое отправляет трафик
        target_ip = socket.gethostbyname(address)
        source_ip = PortChecker.get_local_ip(target_ip)
        source_port = random.randint(40000, 65535)

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_sock.setblocking(False)
        except PermissionError:
            print("для Raw TCP-сокетов нужны права администратора / sudo", file=sys.stderr)
            return result

        pending_ports = set(ports)
        send_times = {}
        open_ports = []

        def process_incoming():
            while True:
                try:
                    raw_data, addr = raw_sock.recvfrom(65535)
                except BlockingIOError:
                    break

                # отсеиваем пакеты с чужих ip
                if addr[0] != target_ip:
                    continue
                parsed = PortChecker.parse_tcp_packet(raw_data)

                if not parsed:
                    continue
                resp_source_port, resp_destination_port, resp_ack_num, flags = parsed
                # проверяем, что ответ адресован именно нашему сканеру и по нужному порту
                if resp_destination_port != source_port or resp_source_port not in pending_ports:
                    continue

                elapsed_ms = int((time.time() - send_times[resp_source_port]) * 1000)

                # syn 0x02 + ack 0x10
                if (flags & 0x12) == 0x12:
                    # сами шлём rst, чтобы явно закрыть соединение
                    rst_packet = PortChecker.build_tcp_packet(
                        source_ip, target_ip, source_port, resp_source_port,
                        flags=0x04, seq=resp_ack_num
                    )
                    try:
                        raw_sock.sendto(rst_packet, (target_ip, 0))
                    except Exception:
                        pass
                    open_ports.append((resp_source_port, elapsed_ms))
                    pending_ports.remove(resp_source_port)
                # rst 0x04 порт закрыт
                elif flags & 0x04:
                    result.append((resp_source_port, False, "-", 0))
                    pending_ports.remove(resp_source_port)

        try:
            batch_size = 5
            batch_delay = 0.005
            # Спамим по 5 портам, затем ждём выгружаем пришедшие и снова (чтобы буффер не терял ответы)
            for idx, port in enumerate(ports, 1):
                packet = PortChecker.build_tcp_packet(source_ip, target_ip, source_port, port)
                try:
                    raw_sock.sendto(packet, (target_ip, 0))
                    send_times[port] = time.time()
                except Exception:
                    # порт закрыт
                    pending_ports.remove(port)
                    result.append((port, False, "-", 0))
                    continue
                if idx % batch_size == 0:
                    pace_until = time.time() + batch_delay
                    while True:
                        wait = pace_until - time.time()
                        if wait <= 0:
                            break
                        ready, _, _ = select.select([raw_sock], [], [], wait)
                        if ready:
                            process_incoming()
                        else:
                            break

            end_time = time.time() + timeout

            # ждём селектом
            while pending_ports:
                remaining_time = end_time - time.time()
                if remaining_time <= 0:
                    break

                ready, _, _ = select.select([raw_sock], [], [], remaining_time)
                if not ready:
                    break
                process_incoming()

            # не было syn ack полагаем, что закрыт
            for port in pending_ports:
                result.append((port, False, "-", 0))
        finally:
            raw_sock.close()

        for port, elapsed_ms in open_ports:
            proto = PortChecker.guess_tcp_protocol(target_ip, port, timeout) if is_guess else "-"
            result.append((port, True, proto, elapsed_ms))

        return result
