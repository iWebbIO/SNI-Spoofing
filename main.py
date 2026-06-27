import asyncio
import os
import socket
import sys
import traceback
import threading
import json
import ctypes
import subprocess
import time

# from utils.proxy_protocols import parse_vless_protocol
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


# Build the path to config.json
config_path = os.path.join(get_exe_dir(), 'config.json')

# Load the config
with open(config_path, 'r') as f:
    config = json.load(f)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    break
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                await loop.sock_sendall(sock_2, data)
            except (ConnectionResetError, OSError, asyncio.CancelledError):
                break
    except Exception:
        traceback.print_exc()
        sys.exit("relay main loop error!")
    finally:
        if peer_task and not peer_task.done():
            for sock in (sock_1, sock_2):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        sock_1.close()
        sock_2.close()


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    try:
        loop = asyncio.get_running_loop()
        # try:
        #     data = await loop.sock_recv(incoming_sock, 65575)
        #     if not data:
        #         raise ValueError("eof")
        # except Exception:
        #     incoming_sock.close()
        #     return
        # try:
        #     version, uuid_bytes, transport_protocol, remote_address_type, remote_address, remote_port, payload_index = parse_vless_protocol(
        #         data)
        # except Exception as e:
        #     print("No Vless Request!, Connection Closed", repr(e), data)
        #     incoming_sock.close()
        #     return
        # if transport_protocol != "tcp":
        #     print("Transport Protocol Error!, Connection Closed", transport_protocol, data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "hostname":
        #     print("hostname address not implemented yet!", data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "ipv4":
        #     if not INTERFACE_IPV4:
        #         print("no interface ipv4!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET
        #     src_ip = INTERFACE_IPV4
        #
        # elif remote_address_type == "ipv6":
        #     if not INTERFACE_IPV6:
        #         print("no interface ipv6!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET6
        #     src_ip = INTERFACE_IPV6
        #
        # else:
        #     print(data)
        #     sys.exit("impossible address type!")

        # try:
        #     fake_sni_host, data_mode, bypass_method = UUID_FAKE_MAP[uuid_bytes]
        # except KeyError:
        #     print("unmatched uuid", uuid_bytes)
        #     incoming_sock.close()
        #     return

        # if data_mode == "http":
        #     ...
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            sys.exit("impossible mode!")
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
            outgoing_sock.close()
            incoming_sock.close()
            return

        # if bypass_method == "wrong_checksum":
        #     ...

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
                else:
                    sys.exit("impossible t2a msg!")
            except Exception:
                fake_injective_conn.monitor = False
                del fake_injective_connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False
        del fake_injective_connections[fake_injective_conn.id]

        # early_data = data[payload_index:]
        # if early_data:
        #     try:
        #         sent_len = await loop.sock_sendall(outgoing_sock, early_data)
        #         if sent_len != len(early_data):
        #             raise ValueError("incomplete send")
        #     except Exception:
        #         outgoing_sock.close()
        #         incoming_sock.close()
        #         return

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))  # bytes([version, 0])
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")



    except Exception:
        traceback.print_exc()
        sys.exit("handle should not raise exception")


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        asyncio.create_task(handle(incoming_sock, addr))


def is_admin() -> bool:
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return os.getuid() == 0
        except AttributeError:
            return False


def run_as_admin():
    if os.name == 'nt':
        try:
            if getattr(sys, 'frozen', False):
                # Executable mode
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv[1:]), None, 1
                )
            else:
                # Script mode
                script = sys.argv[0]
                params = f'"{script}" ' + " ".join([f'"{arg}"' for arg in sys.argv[1:]])
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, params, None, 1
                )
            if int(ret) <= 32:
                print("Administrator privileges were denied. Exiting.")
                sys.exit(1)
            else:
                sys.exit(0)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
            sys.exit(1)
    else:
        print("Please run this script as root/administrator.")
        sys.exit(1)


def get_adapters():
    # Returns a list of dictionaries: [{'IPAddress': '...', 'InterfaceAlias': '...'}]
    cmd = ["powershell", "-Command", "Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress, InterfaceAlias | ConvertTo-Json"]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        if res.stdout.strip():
            data = json.loads(res.stdout)
            if isinstance(data, dict):
                return [data]
            return data
    except Exception:
        pass
    return []


def get_real_default_interface(connect_ip="8.8.8.8") -> tuple[str, str]:
    # Returns (InterfaceAlias, IPAddress)
    adapters = get_adapters()
    ip_to_name = {a['IPAddress']: a['InterfaceAlias'] for a in adapters if 'IPAddress' in a and 'InterfaceAlias' in a}
    name_to_ips = {}
    for a in adapters:
        if 'IPAddress' in a and 'InterfaceAlias' in a:
            name_to_ips.setdefault(a['InterfaceAlias'], []).append(a['IPAddress'])

    def is_proxy_tun(name: str) -> bool:
        name_lower = name.lower()
        return any(x in name_lower for x in ["xray", "sing", "wintun", "tun", "tap", "loopback", "pseudo"])

    routes = []
    cmd = ["powershell", "-Command", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object NextHop, InterfaceAlias, RouteMetric | ConvertTo-Json"]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        if res.stdout.strip():
            routes_data = json.loads(res.stdout)
            if isinstance(routes_data, dict):
                routes = [routes_data]
            elif isinstance(routes_data, list):
                routes = routes_data
    except Exception:
        pass

    physical_routes = []
    for r in routes:
        name = r.get('InterfaceAlias', '')
        if name and not is_proxy_tun(name):
            physical_routes.append(r)

    if physical_routes:
        physical_routes.sort(key=lambda x: x.get('RouteMetric', 9999))
        best_name = physical_routes[0]['InterfaceAlias']
        ips = name_to_ips.get(best_name, [])
        for ip in ips:
            if not ip.startswith("169.254") and not ip.startswith("127."):
                return best_name, ip

    for name, ips in name_to_ips.items():
        if not is_proxy_tun(name):
            for ip in ips:
                if not ip.startswith("169.254") and not ip.startswith("127."):
                    return name, ip

    try:
        default_ip = get_default_interface_ipv4(connect_ip)
        if default_ip:
            name = ip_to_name.get(default_ip, "Unknown")
            return name, default_ip
    except Exception:
        pass

    return "Unknown", ""


def select_network_interface() -> tuple[str, str]:
    adapters = get_adapters()
    adapter_ips = {}
    for a in adapters:
        name = a.get('InterfaceAlias')
        ip = a.get('IPAddress')
        if name and ip:
            adapter_ips.setdefault(name, []).append(ip)

    # Fallback if powershell command returned nothing (e.g. not on Windows)
    if not adapter_ips:
        try:
            hostname = socket.gethostname()
            ips = socket.gethostbyname_ex(hostname)[2]
            adapter_ips['Default Adapter'] = ips
        except Exception:
            pass

    if 'Loopback Pseudo-Interface 1' not in adapter_ips and 'Loopback' not in adapter_ips:
        for name in list(adapter_ips.keys()):
            if 'loopback' in name.lower() or 'pseudo' in name.lower():
                break
        else:
            adapter_ips['Loopback Pseudo-Interface 1'] = ['127.0.0.1']

    default_name, default_ip = get_real_default_interface(CONNECT_IP)

    print("Available network interfaces:")
    names_list = list(adapter_ips.keys())
    for idx, name in enumerate(names_list, 1):
        ips = adapter_ips[name]
        ip_str = ", ".join(ips)
        is_default = " (Default)" if name == default_name else ""
        print(f"{idx}. {name}: {ip_str}{is_default}")

    default_prompt = f" [Default: {default_name}]" if default_name else ""
    while True:
        try:
            choice = input(f"Select network interface (1-{len(names_list)}){default_prompt}: ").strip()
            if not choice:
                if default_name:
                    for ip in adapter_ips.get(default_name, []):
                        if not ip.startswith("169.254"):
                            print(f"Using default network interface: {default_name} ({ip})")
                            return default_name, ip
                    ip = adapter_ips.get(default_name, [""])[0]
                    print(f"Using default network interface: {default_name} ({ip})")
                    return default_name, ip
                else:
                    print("No default interface available. Please make a selection.")
                    continue
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(names_list):
                selected_name = names_list[choice_idx]
                ips = adapter_ips[selected_name]
                selected_ip = ""
                for ip in ips:
                    if not ip.startswith("169.254"):
                        selected_ip = ip
                        break
                if not selected_ip and ips:
                    selected_ip = ips[0]
                print(f"Using network interface: {selected_name} ({selected_ip})")
                return selected_name, selected_ip
            else:
                print(f"Invalid selection. Please enter a number between 1 and {len(names_list)}.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")


fake_tcp_injector = None
injector_thread = None


def run_injector_safe(w_filter, connections):
    global fake_tcp_injector
    try:
        fake_tcp_injector = FakeTcpInjector(w_filter, connections)
        fake_tcp_injector.run()
    except Exception as e:
        print(f"\n[Info] Injector stopped: {e}")


def stop_injector():
    global fake_tcp_injector
    if fake_tcp_injector:
        try:
            fake_tcp_injector.w.close()
        except Exception:
            pass
        fake_tcp_injector = None


def start_injector(ip: str):
    global fake_tcp_injector, injector_thread
    w_filter = "tcp and " + "(" + "(ip.SrcAddr == " + ip + " and ip.DstAddr == " + CONNECT_IP + ")" + " or " + "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + ip + ")" + ")"
    print(f"\n[Info] Starting Fake TCP Injector with filter: {w_filter}")
    injector_thread = threading.Thread(
        target=run_injector_safe,
        args=(w_filter, fake_injective_connections),
        daemon=True
    )
    injector_thread.start()


def monitor_adapter_loop(adapter_name: str, initial_ip: str):
    global INTERFACE_IPV4
    last_ip = initial_ip

    if last_ip:
        start_injector(last_ip)
    else:
        print(f"\n[Warning] Adapter '{adapter_name}' is currently disconnected. Waiting for it to connect...")

    while True:
        time.sleep(2)
        current_ip = ""
        try:
            adapters = get_adapters()
            for a in adapters:
                if a.get('InterfaceAlias') == adapter_name:
                    ip = a.get('IPAddress')
                    if ip and not ip.startswith("169.254"):
                        current_ip = ip
                        break
        except Exception:
            pass

        if last_ip and not current_ip:
            print(f"\n[Warning] Adapter '{adapter_name}' disconnected! Pausing tunnel...")
            stop_injector()
            last_ip = ""
            INTERFACE_IPV4 = ""

        elif current_ip and current_ip != last_ip:
            if not last_ip:
                print(f"\n[Info] Adapter '{adapter_name}' connected (IP: {current_ip}). Resuming tunnel...")
            else:
                print(f"\n[Info] Adapter '{adapter_name}' IP changed from {last_ip} to {current_ip}. Rebinding tunnel...")
                stop_injector()

            INTERFACE_IPV4 = current_ip
            last_ip = current_ip
            start_injector(current_ip)


if __name__ == "__main__":
    if not is_admin():
        print("This application requires administrator privileges. Attempting to elevate...")
        run_as_admin()

    INTERFACE_NAME, INTERFACE_IPV4 = select_network_interface()

    # Start the adapter monitoring and rebinding loop in a daemon thread
    threading.Thread(
        target=monitor_adapter_loop,
        args=(INTERFACE_NAME, INTERFACE_IPV4),
        daemon=True
    ).start()

    print("هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا")
    print(
        "دراد امش تیامح هب زاین هک مراد رظن رد دازآ تنرتنیا هب ناریا مدرم مامت یسرتسد یارب یدایز یاه همانرب و اه هژورپ")
    print("\n")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424\n")
    print("@patterniha")
    asyncio.run(main())
