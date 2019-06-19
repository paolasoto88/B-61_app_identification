import dpkt
import os
import numpy as np
import struct
from benchmark.const import TOR_TRAFFIC_LABELS, TRAFFIC_CLASES, APP_IDENTIFICATION_LABELS, TRAFFIC_CLASES_LABELS, \
    ETHERNET_TYPES
import csv
import json


def mask_ip_addrr(byte_array):
    # Convert Bytes to array of integers
    arr = np.frombuffer(byte_array, dtype=np.uint8)
    # Shuffle the order of bytes
    np.random.shuffle(arr)
    # Pack again into bytes
    shuffled = struct.pack('>B', arr[0])
    for i in range(1, len(arr)):
        shuffled += struct.pack('>B', arr[i])
    return shuffled

def get_label_from_file_path(file_path, out_dir="./out_dir/"):
    """
    Creates the labels for the pcap file ...
    path[str]/appname[str]/trafficClass[str]/vpn[bool]  --> normal apps
    path[str]/appname[str] ---> apps within tor

    :param file_path:
    :param out_dir:
    :return:
    """
    fn = file_path.split('/')[-1].rstrip().lower()
    label_non_tor = []
    label_tor = []

    if 'tor' in fn and 'torrent' not in fn:
        # create output dir if it's not created yet
        app_dir = os.path.join(out_dir, 'tor')

        # create non tor labels
        # path
        label_non_tor.append(app_dir)
        # appname
        label_non_tor.append('tor')
        # trafficClass
        label_non_tor.append('n/a')
        # vpn traffic?
        label_non_tor.append(0)
        for appname in TOR_TRAFFIC_LABELS:
            if appname in fn:
                tor_app_dir = os.path.join(app_dir, appname)
                # create folder if it's not created yet
                if not os.path.exists(tor_app_dir):
                    os.makedirs(tor_app_dir)
                tor_app_dir = os.path.join(tor_app_dir, 'packets.csv')
                label_non_tor[0] = tor_app_dir
                # create tor labels
                label_tor.append(tor_app_dir)
                label_tor.append(appname)
                break

    elif 'vpn' in fn:
        app_dir = os.path.join(out_dir, 'vpn')
        # create non tor labels
        # path
        label_non_tor.append(app_dir)
        for appname in APP_IDENTIFICATION_LABELS:
            if appname in fn:
                label_non_tor.append(appname)
                for tclass, ac in TRAFFIC_CLASES.items():
                    if tclass in fn:
                        label_non_tor.append(tclass)
                        break
                    elif appname in ac:
                        # Can do this as the apps without class in the dataset belong to only one class
                        # in TRAFFIC_CLASSES.
                        label_non_tor.append(tclass)
                        break
                # vpn traffic?
                label_non_tor.append(1)
                # create output dir if it's not created yet
                app_dir = os.path.join(app_dir, label_non_tor[2])
                if not os.path.exists(app_dir):
                    os.makedirs(app_dir)
                app_dir = os.path.join(app_dir, 'packets.csv')
                label_non_tor[0] = app_dir

    else:
        for appname in APP_IDENTIFICATION_LABELS:
            if appname in fn:
                # create output dir if it's not created yet
                app_dir = os.path.join(out_dir, appname)
                if not os.path.exists(app_dir):
                    os.makedirs(app_dir)
                # create non tor labels
                # path
                app_dir = os.path.join(app_dir, 'packets.csv')
                label_non_tor.append(app_dir)
                label_non_tor.append(appname)
                for tclass, ac in TRAFFIC_CLASES.items():
                    if tclass in fn:
                        label_non_tor.append(tclass)
                        break
                    elif appname in ac:
                        # Can do this as the apps without class in the dataset belong to only one class
                        # in TRAFFIC_CLASSES.
                        label_non_tor.append(tclass)
                        break
                # vpn traffic?
                label_non_tor.append(0)
    tor_info = os.path.join(out_dir, 'tor_filenames.csv')
    non_tor_info = os.path.join(out_dir, 'non_tor_filenames.csv')

    if label_tor:
        with open(tor_info, 'a') as csv_file:
            csv_writer = csv.writer(csv_file, delimiter=',')
            csv_writer.writerow(label_tor)
    if label_non_tor:
        with open(non_tor_info, 'a') as csv_file:
            csv_writer = csv.writer(csv_file, delimiter=',')
            csv_writer.writerow(label_non_tor)

    return label_non_tor, label_tor

def process_ip(ip):
    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    # obtain only IP packets, remove ethernet header as not needed.
    # prints out the result of the processed ip packet
    outcome = 'ip packet successfully processed'

    # Make sure the Ethernet frame contains an IPv4 packet, filter ARP packets
    if not isinstance(ip, dpkt.ip.IP):
        outcome = 'non IP packet type'
        ip_packet = b''
    else:
        # Extract information about IP packet
        ip_packet = struct.pack('>B', ip._v_hl)
        ip_packet += struct.pack('>B', ip.tos)
        ip_packet += struct.pack('>H', ip.len)
        ip_packet += struct.pack('>H', ip.id)
        ip_packet += struct.pack('>H', ip.off)
        ip_packet += struct.pack('>B', ip.ttl)
        ip_packet += struct.pack('>B', ip.p)
        ip_packet += struct.pack('>H', ip.sum)
        ip_packet += mask_ip_addrr(ip.src)
        ip_packet += mask_ip_addrr(ip.dst)
    return outcome, ip_packet

def process_tp(tp):
    tp_segment = struct.pack('>H',0)
    outcome = 'not processed tp packet'
    if isinstance(tp, dpkt.tcp.TCP):
        tp_segment = struct.pack('>H', tp.sport)
        tp_segment += struct.pack('>H', tp.dport)
        tp_segment += struct.pack('>I', tp.seq)
        tp_segment += struct.pack('>I', tp.ack)
        tp_segment += struct.pack('>B', tp.off)
        tp_segment += struct.pack('>B', 0)  # discard TCP flags, set to 0
        tp_segment += struct.pack('>H', tp.win)
        tp_segment += struct.pack('>H', tp.sum)
        tp_segment += struct.pack('>H', tp.urp)
        tp_segment += tp.data
        outcome = 'tp packet successfully processed'
    elif isinstance(tp, dpkt.udp.UDP):
        tp_segment = struct.pack('>H', tp.sport)
        tp_segment += struct.pack('>H', tp.dport)
        tp_segment += struct.pack('>H', tp.ulen)
        tp_segment += struct.pack('>H', tp.sum)
        tp_segment += struct.pack('>QI', 0, 0)  # add 12 bytes
        tp_segment += tp.data
        outcome = 'tp packet successfully processed'
    return outcome, tp_segment

def init_statistics():
    # total of valid samples divided per category.
    total_valid_samples_app = {}
    for label in APP_IDENTIFICATION_LABELS:
        total_valid_samples_app[label] = 0
    total_valid_samples_app['tor'] = 0

    total_valid_samples_tclass = {}
    for label in TRAFFIC_CLASES_LABELS:
        total_valid_samples_tclass[label] = 0
        total_valid_samples_tclass['vpn:' + label] = 0
    # tor traffic
    total_valid_samples_tclass['n/a'] = 0

    # total of invalid samples expressed by reasons
    total_invalid_samples = {}
    total_valid_samples = {}
    total_invalid_samples['not able to open file'] = []
    total_invalid_samples['DNS packets'] = {}
    total_invalid_samples['non ip packets'] = {}
    total_invalid_samples['non tp packets'] = {}
    total_valid_samples['total packets in pcap'] = {}
    total_valid_samples['total valid packets in pcap'] = {}
    return total_valid_samples_app, total_valid_samples_tclass, total_invalid_samples, total_valid_samples

def preprocessing(in_dir, out_dir="./"):
    """
    Processes an input directory containing pcap files and store the extracted information in out_dir

    Parameters:
    -----------
    :param in_dir: str: input directory containing pcap files
    :param out_dir: str: output directory where the preprocess data is going to be stored.

    :return:
    """

    # total of valid samples divided per category.
    total_valid_samples_app, total_valid_samples_tclass, total_invalid_samples, total_valid_samples = init_statistics()

    for root, dir, files in os.walk(in_dir):
        for file in files:
            # exclude other kind of files
            print('Processing file: {}'.format(file))
            if '.pcap' in file:
                path_file = os.path.join(in_dir, file)
                testcap = open(path_file, 'rb')
                # Filter pcap-ng packages and read them properly
                try:
                    if file.endswith('ng'):
                        pcap_file = dpkt.pcapng.Reader(testcap)
                    else:
                        pcap_file = dpkt.pcap.Reader(testcap)
                except:
                    if 'not able to open file' not in total_invalid_samples:
                        total_invalid_samples['not able to open file'].append(path_file)
                    else:
                        total_invalid_samples['not able to open file'].append(path_file)
                    continue


                len_mod_packet = []
                dns_counter = 0
                non_ip = 0
                non_tp = 0
                processed_pakets = 0
                valid = 0

                # Get labels
                label_non_tor , label_tor = get_label_from_file_path(path_file, out_dir)

                # Process every pcap to obtain the raw packets.
                # For each packet in the pcap process the contents
                for timestamp, packet in pcap_file:
                    # Basically we have to transfer the data from the original packet to another structure
                    # that allows pre-processing (Mask IP, remove optional header in TCP, etc).

                    # Unpack the Ethernet frame (mac src/dst, ethertype)
                    # Data-link header removal (a)
                    processed_pakets += 1

                    eth = dpkt.ethernet.Ethernet(packet)

                    # Process IP packet
                    if eth.type not in ETHERNET_TYPES.keys():
                        try:
                            ip = dpkt.ip.IP(packet)
                        except:
                            continue
                            # todo: add to statistics?
                    else:
                        ip = eth.data

                    out, ip_packet = process_ip(ip)
                    if out == 'non IP packet type':
                        non_ip += 1
                        continue

                    # Process transport packets
                    tp = ip.data
                    # Discard DNS segments (c)
                    if isinstance(tp, dpkt.udp.UDP):
                        if tp.dport == 53 or tp.sport == 53:
                            dns_counter += 1
                            continue

                    # Filter tcp and udp packets - modify them (b)
                    out, tp_segment = process_tp(tp)

                    if out == 'tp packet successfully processed':

                        # Count of valid samples
                        if label_non_tor:
                            valid +=1
                            if label_non_tor[3] != 0:
                                # vpn traffic
                                total_valid_samples_tclass['vpn:' + label_non_tor[2]] += 1
                            else:
                                total_valid_samples_app[label_non_tor[1]] += 1
                                total_valid_samples_tclass[label_non_tor[2]] += 1


                        # concatenate ip and transport
                        mod_packet = ip_packet + tp_segment

                        # convert to integer (d)
                        # todo: normalize in the pre-processing for training, otherwise the file size is too big
                        mod_packet = np.frombuffer(mod_packet, dtype=np.uint8)

                        len_mod_packet.append(len(mod_packet))

                        if len(mod_packet) >= 1500:
                            #truncate
                            mod_packet = mod_packet[:1500]
                        else:
                            # inject zeros
                            dif = 1500 - len(mod_packet)
                            mod_packet = np.append(mod_packet, np.zeros(dif))


                        # Dump info to csv
                        # Output directory
                        category_out_dir = label_non_tor[0]

                        # Store raw packets
                        #output_fn = 'packets.csv'
                        with open(category_out_dir, 'a') as csv_file:
                            csv_writer = csv.writer(csv_file, delimiter=',')
                            csv_writer.writerow(mod_packet)
                    else:
                        non_tp += 1
                with open(os.path.join(out_dir, 'results.txt'), 'a') as text_file:
                    text_file.write(str(len_mod_packet))
                    text_file.write("\n")
                total_invalid_samples['DNS packets'][path_file] = dns_counter
                total_invalid_samples['non ip packets'][path_file] = non_ip
                total_invalid_samples['non tp packets'][path_file] = non_tp
                total_valid_samples['total packets in pcap'][path_file] = processed_pakets
                total_valid_samples['total valid packets in pcap'][path_file] = valid

    with open(os.path.join(out_dir, 'results.txt'), 'a') as text_file:
        text_file.write('Total valid samples per app:')
        text_file.write(json.dumps(total_valid_samples_app))
        text_file.write("\n")
        text_file.write('Total valid samples per class:')
        text_file.write(json.dumps(total_valid_samples_tclass))
        text_file.write("\n")
        text_file.write('Total invalid samples:')
        text_file.write(json.dumps(total_invalid_samples))
        text_file.write("\n")
        text_file.write('Total valid samples per pcap:')
        text_file.write(json.dumps(total_valid_samples))

