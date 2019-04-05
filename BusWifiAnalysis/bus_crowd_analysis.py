
import os
import re
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import json
from collections import Counter
import numpy as np

# Paths constants
base_input_folder = 'D:\BusCrowdProject\inputs'
current_run_folder = 'second_run'
current_run_path = os.path.join(base_input_folder, current_run_folder)
ground_truth_file_name = 'ground_truth.txt'
all_pkt_summary_file_name = 'all_packets_summary'
mgmt_pkt_summary_file_name = 'mgmt_packets_summary'
probe_pkt_summary_file_name = 'probe_packets_summary'
probe_pkt_detailed_file_name = 'probe_packets_detailed'
ble_data_file_name = 'ble data.txt'


# Regex patterns
ground_truth_file_line = r'^([0-9]+\/[0-9]+\/[0-9]+ [0-9]+:[0-9]+:[0-9]+ [AP]M)[ \t]+([0-9]+)$'
packet_timestamp = r'.+ ([0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+)[.][0-9]+ .+'
ble_data_file_line = r'([0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+)\S+\s(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))\s([-][0-9]+)'


# Useful info in a probe packet
class ProbePacketInfo:
    def __init__(self, probe_packet_json):

        # Detect malformed packets.
        self.malformed = False
        x = findkeys(probe_packet_json, "_ws.malformed")
        if next(x, None) is not None:
            self.malformed = True

        # Basic info
        time_since_epoch = float(next(findkeys(probe_packet_json, "frame.time_epoch")))
        self.timestamp = datetime.fromtimestamp(time_since_epoch)

        self.mac_address = self.deal_with_parsing_failure(lambda: next(findkeys(probe_packet_json, "wlan.sa")))
        self.frame_len = self.deal_with_parsing_failure(lambda: int(next(findkeys(probe_packet_json, "frame.len"))))
        self.signal_strength = self.deal_with_parsing_failure(lambda: int(next(findkeys(probe_packet_json, "wlan_radio.signal_dbm"))))
        self.duration = self.deal_with_parsing_failure(lambda: int(next(findkeys(probe_packet_json, "wlan_radio.duration"))))
        self.cluster_id = None

    def deal_with_parsing_failure(self, lambda_exp):
        # If the packet is malformed, go easy on the parsing errors.
        try:
            return lambda_exp()
        except:
            if not self.malformed:
                raise
            return None


#################### Utilities ########################

# Find a key in a dict of nested dicts.
def findkeys(node, kv):
    if isinstance(node, list):
        for i in node:
            for x in findkeys(i, kv):
               yield x
    elif isinstance(node, dict):
        if kv in node:
            yield node[kv]
        for j in node.values():
            for x in findkeys(j, kv):
                yield x


# Deal with duplicate keys in JSON data by changing keys
def dict_raise_on_duplicates(ordered_pairs):
    d = {}
    for k, v in ordered_pairs:
        new_key = k
        i = 1
        while new_key in d:
            new_key = k + str(i)
            i += 1

        d[new_key] = v
    return d


# Plot frequency of elements in a list
def plot_freq(list_data):
    x_values = sorted(set(list_data))
    y_values = []
    for x in x_values:
        y_values.append(list_data.count(x))
    plt.bar(x_values, y_values)
    plt.show()



#################### Ground truth related ##########################

def read_groud_truth_data():
    ground_truth = {}
    truth_file_path = os.path.join(current_run_path, ground_truth_file_name)
    with open(truth_file_path, "r") as lines:
        for line in lines:
            matches = re.match(ground_truth_file_line, line)
            if matches:
                time_string = matches.group(1)
                time_stamp = datetime.strptime(time_string, '%m/%d/%Y %I:%M:%S %p')
                value = int(matches.group(2))
                ground_truth[time_stamp] = value

    min_time = min(ground_truth.keys()) - timedelta(seconds=60)
    max_time = max(ground_truth.keys()) + timedelta(seconds=60)

    all_readings = []
    last_value = 0
    duration_seconds = (max_time - min_time).seconds
    for seconds in range(duration_seconds):
        time = min_time + timedelta(seconds=seconds)
        if time in ground_truth.keys():
            last_value = ground_truth[time]
        all_readings.append([time, "ground_truth", last_value])

    return all_readings


###################### Wi-Fi data related ################################

def get_packet_counts():
    packet_count = {}
    file_path = os.path.join(current_run_path, all_pkt_summary_file_name)
    with open(file_path, "r") as lines:
        for line in lines:
            matches = re.match(packet_timestamp, line)
            if matches:
                time_string = matches.group(1)
                time_stamp_to_sec = datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S')
                time_stamp_to_minute = time_stamp_to_sec.replace(second=0)
                time_stamp_to_use = time_stamp_to_minute
                if time_stamp_to_use in packet_count.keys():
                    packet_count[time_stamp_to_use] += 1
                else:
                    packet_count[time_stamp_to_use] = 1

    return [[t, "pkt_count",  packet_count[t]] for t in packet_count.keys()]


def get_probe_packets_detailed():
    file_path = os.path.join(current_run_path, probe_pkt_detailed_file_name)
    packets_json = json.load(open(file_path, "r"), object_pairs_hook=dict_raise_on_duplicates)
    packets = [ProbePacketInfo(pkt_json) for pkt_json in packets_json]
    # plt.hist(list(map(lambda l: l.mac_address, packets)), bins=250)
    # plot_freq(list(map(lambda l: l.mac_address, packets)))
    return packets


def parse_and_plot_wifi_results():
    fig, (ax1, ax3) = plt.subplots(2, 1)
    fig.suptitle("Wi-Fi Device Estimation")

    # Plot ground truth
    all_readings = read_groud_truth_data()
    truth_times = list(map(lambda r: r[0], filter(lambda r: r[1] == "ground_truth", all_readings)))
    truth_values = list(map(lambda r: r[2], filter(lambda r: r[1] == "ground_truth", all_readings)))
    ax1.plot(truth_times, truth_values, color="black")
    ax1.set_ylabel("Actual Passenger Count")

    # Plot wifi pkt count
    # all_readings = get_packet_counts()
    # pkt_count_times = list(map(lambda r: r[0], filter(lambda r: r[1] == "pkt_count", all_readings)))
    # pkt_count_values = list(map(lambda r: r[2], filter(lambda r: r[1] == "pkt_count", all_readings)))
    # ax2.plot(pkt_count_times, pkt_count_values)
    # ax2.set_ylabel("Packet count")
    # output_plot_path = os.path.join(base_input_folder, "plots", "Exp2_probe_pkt_count.png")


    # Parse probe packets
    packets = get_probe_packets_detailed()

    # Clustering based on true mac addresses.
    true_mac_packets = filter_true_mac_addr_packets(packets)
    for pkt in true_mac_packets:
        pkt.cluster_id = pkt.mac_address

    # Plot
    times, devices_count = evaluate_crowd_from_packet_clusters(true_mac_packets)
    ax3.plot(times, devices_count, color="black")
    ax3.set_ylabel("Devices estimate")

    plt.show()
    # plt.savefig(output_plot_path)


def analyze_wifi_results():

    # Parse probe packets
    packets = get_probe_packets_detailed()

    # Clustering based on true mac addresses.
    true_mac_packets = filter_true_mac_addr_packets(packets)
    for pkt in true_mac_packets:
        pkt.cluster_id = pkt.mac_address

    # Plot
    times, devices_count = evaluate_crowd_from_packet_clusters(true_mac_packets)


# True mac address is any address that has more than one packet.
def filter_true_mac_addr_packets(all_packets):
    all_mac_addrs = [p.mac_address for p in all_packets]
    mac_addrs_counter = Counter(all_mac_addrs)
    true_mac_addrs = [k for k in mac_addrs_counter.keys() if k is not None and mac_addrs_counter[k] > 1]
    print(mac_addrs_counter.__len__(), true_mac_addrs.__len__())
    true_mac_packets = [p for p in all_packets if p.mac_address in true_mac_addrs]
    return true_mac_packets


# Given clustered packets (based on some kind of probe packet clustering), one cluster for each device -> evaluates and
# plots estimated crowd. Takes in list of ProbePacketInfo with cluster_id info set.
def evaluate_crowd_from_packet_clusters(clustered_packets):

    # Collect set of timestamps for each cluster
    start_time = datetime.max
    end_time = datetime.min
    cluster_timestamps = {}
    for pkt in clustered_packets:
        time_stamp_to_sec = pkt.timestamp.replace(microsecond=0)
        # print(time_stamp_to_sec, ",", pkt.cluster_id)
        if pkt.cluster_id in cluster_timestamps.keys():
            cluster_timestamps[pkt.cluster_id].append(time_stamp_to_sec)
        else:
            cluster_timestamps[pkt.cluster_id] = [time_stamp_to_sec]

        if time_stamp_to_sec < start_time:
            start_time = time_stamp_to_sec
        if time_stamp_to_sec > end_time:
            end_time = time_stamp_to_sec

    # Plot intervals
    cluster_intervals = {}
    for cluster_id, timestamps in cluster_timestamps.items():
        last_time = timestamps[0]
        for current_time in timestamps[1:]:
            seconds = (current_time - last_time).seconds
            if cluster_id in cluster_intervals.keys():
                cluster_intervals[cluster_id].append(seconds)
            else:
                cluster_intervals[cluster_id] = [seconds]
            last_time = current_time
            # print(seconds)

    # Filter out clusters for external devices
    start_time_counts = {}
    end_time_counts = {}
    for cluster_id, intervals in cluster_intervals.items():
        min_time = min(cluster_timestamps[cluster_id])
        max_time = max(cluster_timestamps[cluster_id])
        duration = max_time - min_time
        count = cluster_timestamps[cluster_id].__len__()
        print(duration.seconds)

        if duration.seconds < 180 or list(filter(lambda i: i > 180, intervals)).__len__() > 0:
            continue

        # print(cluster_id, count, duration.seconds, duration.seconds / count, min_time, max_time, intervals)
        if min_time in start_time_counts:
            start_time_counts[min_time] += 1
        else:
            start_time_counts[min_time] = 1

        if max_time in end_time_counts:
            end_time_counts[max_time] += 1
        else:
            end_time_counts[max_time] = 1

    # Evaluate number of devices at any point
    times = []
    devices_count = []
    devices_counter = 0
    duration = end_time - start_time
    for seconds in range(duration.seconds):
        current_time = start_time + timedelta(seconds=seconds)
        if current_time in start_time_counts.keys():
            devices_counter += start_time_counts[current_time]
        if current_time in end_time_counts.keys():
            devices_counter -= end_time_counts[current_time]
        times.append(current_time)
        devices_count.append(devices_counter)
        # print(current_time, devices_counter)

    return times, devices_count



##################### Bluetooth data related ################################

def get_ble_scanner_count():
    packet_count = {}
    file_path = os.path.join(current_run_path, ble_data_file_name)
    with open(file_path, "r") as lines:
        for line in lines:
            matches = re.match(ble_data_file_line, line)
            if matches:
                time_string = matches.group(1)
                mac_address = matches.group(2)
                rssi_value = int(matches.group(5))
                time_stamp_to_sec = datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S')
                time_stamp_to_minute = time_stamp_to_sec.replace(second=0)
                time_stamp_to_use = time_stamp_to_minute
                if time_stamp_to_use in packet_count.keys():
                    packet_count[time_stamp_to_use] += 1
                else:
                    packet_count[time_stamp_to_use] = 1

    return [[t, "ble_scan_count",  packet_count[t]] for t in packet_count.keys()]


def parse_ble_data_get_onboard_devices_count():
    # Parse the file
    mac_addr_dict = {}
    file_path = os.path.join(current_run_path, ble_data_file_name)
    start_time = datetime.max
    end_time = datetime.min
    with open(file_path, "r") as lines:
        for line in lines:
            matches = re.match(ble_data_file_line, line)
            if matches:
                time_string = matches.group(1)
                mac_address = matches.group(2)
                rssi_value = int(matches.group(5))

                time_stamp_to_sec = datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S')
                if time_stamp_to_sec < start_time:
                    start_time = time_stamp_to_sec
                if time_stamp_to_sec > end_time:
                    end_time = time_stamp_to_sec

                if mac_address in mac_addr_dict.keys():
                    mac_addr_dict[mac_address].append(time_stamp_to_sec)
                else:
                    mac_addr_dict[mac_address] = [time_stamp_to_sec]

    # Add some padding
    start_time -= timedelta(minutes=1)
    end_time += timedelta(minutes=1)

    # Filter out external devices and record time durations
    start_time_counts = {}
    end_time_counts = {}
    for mac_addr in mac_addr_dict.keys():
        min_time = min(mac_addr_dict[mac_addr])
        max_time = max(mac_addr_dict[mac_addr])
        duration = max_time - min_time
        count = mac_addr_dict[mac_addr].__len__()

        last_time = mac_addr_dict[mac_addr][0]
        for current_time in mac_addr_dict[mac_addr][1:]:
            seconds = (current_time - last_time).seconds
            print(seconds)
            last_time = current_time

        if duration.seconds > 200 and duration.seconds/count < 20:
            if min_time in start_time_counts:
                start_time_counts[min_time] += 1
            else:
                start_time_counts[min_time] = 1

            if max_time in end_time_counts:
                end_time_counts[max_time] += 1
            else:
                end_time_counts[max_time] = 1

    print(start_time_counts)
    print(end_time_counts)

    # Evaluate number of devices at any point
    all_times = []
    devices_counter = 0
    duration = end_time - start_time
    for seconds in range(duration.seconds):
        current_time = start_time + timedelta(seconds=seconds)
        if current_time in start_time_counts.keys():
            devices_counter += start_time_counts[current_time]
        if current_time in end_time_counts.keys():
            devices_counter -= end_time_counts[current_time]
        all_times.append([current_time, "ble_devices_count", devices_counter])
        # print(current_time, devices_counter)

    return all_times


def parse_and_plot_ble_results():
    fig, (ax1, ax2) = plt.subplots(2, 1)
    fig.suptitle("Bluetooth-based device estimation")

    # Plot ground truth
    all_readings = read_groud_truth_data()
    truth_times = list(map(lambda r: r[0], filter(lambda r: r[1] == "ground_truth", all_readings)))
    truth_values = list(map(lambda r: r[2], filter(lambda r: r[1] == "ground_truth", all_readings)))
    ax1.plot(truth_times, truth_values, color="black")
    ax1.set_ylabel("Actual passenger count")

    # Plot wifi pkt count
    # all_readings = get_packet_counts()
    # pkt_count_times = list(map(lambda r: r[0], filter(lambda r: r[1] == "pkt_count", all_readings)))
    # pkt_count_values = list(map(lambda r: r[2], filter(lambda r: r[1] == "pkt_count", all_readings)))
    # ax2.plot(pkt_count_times, pkt_count_values)
    # ax2.set_ylabel("Packet count")
    # output_plot_path = os.path.join(base_input_folder, "plots", "Exp2_probe_pkt_count.png")

    # Plot ble scan count
    # all_readings = get_ble_scanner_count()
    # pkt_count_times = list(map(lambda r: r[0], filter(lambda r: r[1] == "ble_scan_count", all_readings)))
    # pkt_count_values = list(map(lambda r: r[2], filter(lambda r: r[1] == "ble_scan_count", all_readings)))
    # ax2.plot(pkt_count_times, pkt_count_values)
    # ax2.set_ylabel("Scan count")
    # output_plot_path = os.path.join(base_input_folder, "plots", "Exp2_ble_scan_count.png")

    # Plot ble filtered devices count
    all_readings = parse_ble_data_get_onboard_devices_count()
    count_times = list(map(lambda r: r[0], filter(lambda r: r[1] == "ble_devices_count", all_readings)))
    count_values = list(map(lambda r: r[2], filter(lambda r: r[1] == "ble_devices_count", all_readings)))
    ax2.plot(count_times, count_values, color="black")
    ax2.set_ylabel("Devices estimate")
    output_plot_path = os.path.join(base_input_folder, "plots", "ble_devices_estimate.png")

    plt.show()
    # plt.savefig(output_plot_path)


########################## Main #################################

def main():
    # parse_and_plot_ble_results()
    parse_and_plot_wifi_results()
    # analyze_wifi_results()


if __name__ == '__main__':
    main()
