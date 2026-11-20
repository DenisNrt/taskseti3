import argparse
from port_checker import PortChecker


def parse_arguments(arguments):
    def expand_ports(port_string):
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                yield from range(start, end + 1)
            else:
                yield int(part)

    tcp_ports = [
        port
        for item in arguments.ports if item.startswith("tcp")
        for port in (expand_ports(item.split('/')[1]) if '/' in item else range(1, 65536))
    ]
    udp_ports = [
        port
        for item in arguments.ports if item.startswith("udp")
        for port in (expand_ports(item.split('/')[1]) if '/' in item else range(1, 65536))
    ]
    return arguments.timeout, arguments.verbose, arguments.guess, arguments.address, list(set(tcp_ports)), list(
        set(udp_ports))


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Сканирует порты tcp/udp")
    parser.add_argument("-t", "--timeout", default=2, type=float, help="Таймаут ожидания ответа в секундах")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный режим")
    parser.add_argument("-g", "--guess", action="store_true", help="Определение протокола прикладного уровня")
    parser.add_argument("address", type=str, help="IP-адрес")
    parser.add_argument("ports", default=["tcp", "udp"], nargs='*', type=str,
                        help="Порты для сканирования [{tcp|udp}[/[PORT|PORT-PORT],...]]...")
    timeout, is_verbose, is_guess, address, tcp_ports, udp_ports = parse_arguments(parser.parse_args())

    all_results = []
    # отдаём udp порты сканеру
    for res in PortChecker.scan_udp_ports(address, udp_ports, timeout, is_guess):
        all_results.append(("UDP",) + res)

    # отдаём tcp порты сканеру
    for res in PortChecker.scan_tcp_ports(address, tcp_ports, timeout, is_guess):
        all_results.append(("TCP",) + res)

    for prot, port, is_active, protocol, elapsed_ms in sorted(all_results):
        if is_active:
            output = f"{prot} {port}"
            if is_verbose:
                output += f" [{elapsed_ms}ms]"
            if is_guess:
                output += f" [{protocol}]"
            print(output)
