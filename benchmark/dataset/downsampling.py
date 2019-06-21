import os
import csv
import json
import numpy as np
import random
import time

def down_sample(input_dir, output_dir, task=0):
    if task == 1:
        # todo: downsampling is different depending on the task to be done what is coded right now is the application identification task, consider also TOR traffic
        pass

    start = time.time()
    os.makedirs(output_dir, exist_ok=True)

    for root, directories, files in os.walk(input_dir):
        # create the same structure in output_dir
        rel_path = os.path.relpath(root,input_dir)
        out_path = os.path.join(output_dir, rel_path)
        os.makedirs(out_path, exist_ok=True)

        for file in files:
            if file == 'results.txt':
                with open(os.path.join(root, file), 'r') as text_file:
                    for line in text_file.readlines():
                        if line.startswith('Total valid samples per app:'):
                            result = json.loads(line.rstrip().split('Total valid samples per app:')[1])
                            num_valid_packets = np.asarray(list(result.values()))
                            minimum_apps = np.min(num_valid_packets[np.nonzero(num_valid_packets)])
            if file.endswith('.csv'):
                # read the info of the file, load it in memory, [[packet1], [packet2], ...]
                with open (os.path.join(root, file)) as csv_file:
                    csv_reader = csv.reader(csv_file, delimiter=',')
                    packets = []
                    for row in csv_reader:
                        packets.append(row)
                # select a minimum number of random samples (down sampling)
                random_samples = random.sample(packets, minimum_apps)
                # store them in other directory
                with open(os.path.join(out_path, file), 'a') as csv_file:
                    csv_writer = csv.writer(csv_file, delimiter=',')
                    for sample in random_samples:
                        csv_writer.writerow(sample)
                # create labels already created for the two tasks
                # add path
                line = []
                line_tor = []
                line_traffic = []
                line.append(os.path.join(out_path, file))
                line_tor.append(os.path.join(out_path, file))
                line_traffic.append(os.path.join(out_path, file))
                if rel_path.startswith('vpn'):
                    line_traffic.append(rel_path)
                    with open(os.path.join(output_dir, 'labels_traffic.txt'), 'a') as text_file:
                        text_file.write(line_traffic)
                        text_file.write("\n")
                elif rel_path.startswith('tor'):
                    line.append('tor')
                    line_tor.append(rel_path)
                    with open(os.path.join(output_dir, 'labels_app.txt'), 'a') as text_file:
                        text_file.write(line)
                        text_file.write("\n")
                    with open(os.path.join(output_dir, 'labels_tor.txt'), 'a') as text_file:
                        text_file.write(line_tor)
                        text_file.write("\n")
                else:
                    # todo: normal app and traff labels
                    line.append(rel_path)
                    with open(os.path.join(output_dir, 'labels_app.txt'), 'a') as text_file:
                        text_file.write(line)
                        text_file.write("\n")
                    line_traffic.append()
                    with open(os.path.join(output_dir, 'labels_traffic.txt'), 'a') as text_file:
                        text_file.write(line_traffic)
                        text_file.write("\n")
                    pass

    end = time.time()
    print('Downsampling data took: {} seconds'.format(end - start))