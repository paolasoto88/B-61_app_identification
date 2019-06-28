import os
import csv
import json
import numpy as np
import random
import time
from bbudget.const import APP_IDENTIFICATION_LABELS, TOR_TRAFFIC_LABELS, TRAFFIC_CLASES_LABELS

def create_categories(task):
    categories = []
    if task == 0:
        categories = APP_IDENTIFICATION_LABELS
        categories.append('tor')
    elif task == 1:
        for tclass in TRAFFIC_CLASES_LABELS:
            categories.append(tclass)
            categories.append('vpn_' + tclass)
    elif task == 2:
        categories = TOR_TRAFFIC_LABELS
    else:
        raise NotImplementedError
    return categories


def get_min_packets_per_cat(path_file, task):
    min_pkts = 0
    with open(path_file, 'r') as text_file:
        for line in text_file.readlines():
            if task == 0:
                if line.startswith('Total valid samples per app:'):
                    result = json.loads(line.rstrip().split('Total valid samples per app:')[1])
                    num_valid_packets = np.asarray(list(result.values()))
                    min_pkts = np.min(num_valid_packets[np.nonzero(num_valid_packets)])
            elif task == 1:
                if line.startswith('Total valid samples per class:'):
                    result = json.loads(line.rstrip().split('Total valid samples per class:')[1])
                    num_valid_packets = np.asarray(list(result.values()))
                    min_pkts = np.min(num_valid_packets[np.nonzero(num_valid_packets)])
            else:
                raise NotImplementedError
    return min_pkts, result


def group_per_cat(input_dir, categories, task):
    files_per_cat = {}
    for root, dirs, files in os.walk(input_dir):
        for category in categories:
            files_per_cat[category] = []
            for file in files:
                cat = file.split('.')[0].split('_')
                if task == 0:
                    # not vpn traffic
                    if cat[-1] != '1' and cat[0] == category:
                        files_per_cat[category].append(os.path.join(root, file))
                elif task == 1:
                    # not include tor traffic
                    if cat[0] != 'tor':
                        if cat[1] == category and cat[-1] == '0':
                            files_per_cat[category].append(os.path.join(root, file))
                        else:
                            # vpn cat
                            if cat[-1] == '1' and category.startswith('vpn'):
                                if cat[1] in category:
                                    files_per_cat[category].append(os.path.join(root, file))
                else:
                    if cat[0] == 'tor':
                        files_per_cat[category].append(os.path.join(root, file))
    return files_per_cat


def create_train_dataset_labels(folder, information, label):
    with open(os.path.join(folder, 'dataset.csv'), 'a') as packets_file, open(
            os.path.join(folder, 'labels.csv'), 'a') as labels_file:
        packets_file.write(information)
        labels_file.write(label)
        labels_file.write('\n')

def down_sample(input_dir, output_dir, task=0):
    '''Script to down sample the data set
    ==================================

    '''
    start = time.time()
    # get the categories to classify according to the type of task
    categories = create_categories(task)
    # get the min number of packet per category
    result = {}
    min_num_pkt = 0
    for file in os.listdir(input_dir):
        if file == 'results.txt':
            path_file = os.path.join(input_dir, file)
            min_num_pkt, result = get_min_packets_per_cat(path_file, task)


    raw_folder = os.path.join(input_dir, 'raw_packets')
    files_per_cat = group_per_cat(raw_folder, categories, task)

    if task == 0:
        output_dir = os.path.join(output_dir, 'app')
    elif task == 1:
        output_dir = os.path.join(output_dir, 'traffic')
    else:
        raise NotImplementedError
    os.makedirs(output_dir, exist_ok=True)

    for cat in files_per_cat:
        try:
            # select certain number of packets according to a probability, avoids to load info to memory
            total_pkts = result[cat]
            pr = min_num_pkt / total_pkts
            for file in files_per_cat[cat]:
                print(file)
                count = 0
                with open(file) as csv_file:
                    for line in csv_file:
                        p = random.random()
                        if p <= pr:
                            count += 1
                            create_train_dataset_labels(output_dir, line, cat)
                print(count)
        except:
            print('not ready yet')
    end = time.time()
    print('Downsampling data took: {} seconds'.format(end - start))