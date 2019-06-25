import os
import csv
import json
import numpy as np
import random
import time
from benchmark.const import APP_IDENTIFICATION_LABELS, TOR_TRAFFIC_LABELS, TRAFFIC_CLASES, TRAFFIC_CLASES_LABELS

def create_train_dataset_labels(folder, information, label):
    with open(os.path.join(folder, 'dataset.csv'), 'a') as packets_file, open(
            os.path.join(folder, 'labels.csv'), 'a') as labels_file:
        packets_writer = csv.writer(packets_file, delimiter=',')
        labels_writer = csv.writer(labels_file, delimiter=',')
        for sample in information:
            packets_writer.writerow(sample)
            labels_writer.writerow(label)
    return

def save_path(path_file, save_dest, label):
    with open(os.path.join(save_dest, label + '_files.txt'), 'a') as file:
        file.write(path_file)
        file.write("\n")

def get_min_packets_per_cat(path_file):
    with open(path_file, 'r') as text_file:
        for line in text_file.readlines():
            if line.startswith('Total valid samples per app:'):
                result = json.loads(line.rstrip().split('Total valid samples per app:')[1])
                num_valid_packets = np.asarray(list(result.values()))
                minimum_app = np.min(num_valid_packets[np.nonzero(num_valid_packets)])
            if line.startswith('Total valid samples per class:'):
                result = json.loads(line.rstrip().split('Total valid samples per class:')[1])
                num_valid_packets = np.asarray(list(result.values()))
                minimum_class = np.min(num_valid_packets[np.nonzero(num_valid_packets)])
    print('Minimum number of packets in application identification task: {}'.format(minimum_app))
    print('Minimum number of packets in traffic classification task: {}'.format(minimum_class))
    return minimum_class, minimum_app

def group_data(input_dir, output_dir, task):

    os.makedirs(output_dir, exist_ok=True)
    app_folder = os.path.join(output_dir, 'app')
    os.makedirs(app_folder, exist_ok=True)
    traffic_folder =  os.path.join(output_dir, 'traffic')
    os.makedirs(traffic_folder, exist_ok=True)
    tor_folder = os.path.join(output_dir, 'tor')
    os.makedirs(tor_folder, exist_ok=True)
    min_tclass = 0
    min_app = 0
    for root, directories, files in os.walk(input_dir):
        for file in files:
            path_file = os.path.join(root, file)
            label = file.split('.')[0].split('_')
            if file == 'results.txt':
                min_tclass, min_app = get_min_packets_per_cat(path_file)
            if file.endswith('.csv'):
                for app in APP_IDENTIFICATION_LABELS:
                    if (label[0]== app and label[-1] != '1') or label[0] == 'tor':
                        save_path(path_file, app_folder, label[0])
                        break
                for tclass in TRAFFIC_CLASES:
                    if label[1] == tclass:
                        if label[-1] == '1':
                            tclass = 'vpn_' + tclass
                        save_path(path_file, traffic_folder, tclass)
                for tor_app in TOR_TRAFFIC_LABELS:
                    if label[-1] == tor_app:
                        save_path(path_file, tor_folder, tor_app)
    if task == 'app':
        minimum = min_app
    elif task == 'traffic':
        minimum = min_tclass
    else:
        minimum = 0 # todo: add tor traffic
    return minimum


def down_sample(input_dir, output_dir, task=0):

    tasks = {0: 'app', 1: 'traffic', 2: 'tor'}
    folder = 'app'
    for t in tasks:
        if task == t:
            folder = tasks[t]
            break
    start = time.time()
    # todo: add more generic behavior, for instance, specify how many samples you want in your dataset, if the size is less than the available packages in the dataset, then use data augmentation.

    load_in_memory(os.path.join(input_dir, 'raw_packets'))
    min_num_pkt = group_data(input_dir, output_dir, folder)

    for root, directories, files in os.walk(os.path.join(output_dir, folder)):
        packets = []
        for file in files:
            if file.endswith('.txt'):
                # open and read the info of the file, load it in memory, [[packet1], [packet2], ...]
                with open(os.path.join(root, file), 'r') as f:
                    for line in f.readlines():
                        line = line.rstrip('\n')
                        label = line.split('.')[0].split('/')[-1].split('_')
                        with open(line) as csv_file:
                            csv_reader = csv.reader(csv_file, delimiter=',')
                            for row in csv_reader:
                                packets.append(row)
                        # select a minimum number of random samples (down sampling)
                        random_samples = random.sample(packets, min_num_pkt)
                        create_train_dataset_labels(root, random_samples, label)
    end = time.time()
    print('Downsampling data took: {} seconds'.format(end - start))

def load_in_memory(input_dir):

    app_labels = APP_IDENTIFICATION_LABELS
    app_labels.append('tor')

    for root, dirs, files in os.walk(input_dir):
        for app in app_labels:
            packets = []
            for file in files:
                cat = file.split('.')[0].split('_')
                if cat[0] == app:
                    print('Processing file: {}'.format(file))
                    with open(os.path.join(root, file), 'r') as csv_file:
                        csv_reader = csv.reader(csv_file, delimiter=',')
                        for row in csv_reader:
                            packets.append(row)
                    print('raw packets successfully loaded for app {}'.format(app))


def create_categories(task):
    if task == 0:
        categories = APP_IDENTIFICATION_LABELS
        categories.append('tor')
    elif task == 1:
        categories = TRAFFIC_CLASES_LABELS
        for tclass in TRAFFIC_CLASES_LABELS:
            categories.append('vpn_'+tclass)
    elif task == 2:
        categories = TOR_TRAFFIC_LABELS
    else:
        raise NotImplementedError
    return categories

def down_sample_(input_dir, output_dir, task=0):
    # create categories to filter
    categories = create_categories(task)

    for root, directories, files in os.walk(input_dir):
        for file in files:
            path_file = os.path.join(root, file)
            label = file.split('.')[0].split('_')
            if file == 'results.txt':
                min_num_pkt = get_min_packets_per_cat(path_file)
            else:
                if file.endswith('.csv'):
                    # todo: modify load_in_memory to accept categories
                    packets = load_in_memory(root)
                    random_samples = random.sample(packets, min_num_pkt)
                    create_train_dataset_labels(root, random_samples, label)