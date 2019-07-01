import os
import pandas as pd
import csv


def read_data(dataset_path, labels_path):
    '''
    This function reads the data saved in a folder
    :param dataset_path: path in disk where the dataset is
    :param labels_path: path in disk where the labels are
    :return: a pandas dataframe
    '''
    with open(dataset_path) as dataset_file, open(labels_path) as labels_file:
        labels = []
        packets = []
        dataset_reader = csv.reader(dataset_file, delimiter=',')
        labels_reader = csv.reader(labels_file, delimiter=',')
        for row in dataset_reader:
            pkt = ''
            for item in row:
                pkt = pkt + item + ','
            packets.append(pkt)
        for row in labels_reader:
            labels.append(row[0])
        info = []
        for i in range(len(labels)):
            info.append((labels[i], packets[i]))
    return pd.DataFrame(info, columns=["label", "packet"])


def make_dirs(inputdir, outputdir):
    task = inputdir.split('/')[-1]
    os.makedirs(os.path.join(outputdir, task), exist_ok=True)
    return os.path.join(outputdir, task)

def create_balanced_split(full_df, val_size, test_size, seed):
    train_dfs = []
    val_dfs = []
    test_dfs = []
    for cat in full_df["label"].unique():
        # create an alternative dataframe with the respective categories
        cat_df = full_df.loc[full_df["label"] == cat]
        # the train split is 1.0 - val_size - test_size
        cat_train_df = cat_df.sample(frac=1.0 - val_size - test_size,
                                     random_state=seed)
        train_dfs.append(cat_train_df)
        # save the remaining samlpes of the data frame
        rem_df = cat_df.drop(cat_train_df.index)
        if rem_df.shape[0] > 0:
            cat_val_df = rem_df.sample(frac=val_size / (val_size + test_size),
                                       random_state=seed)
            cat_test_df = rem_df.drop(cat_val_df.index)
            val_dfs.append(cat_val_df)
            test_dfs.append(cat_test_df)
    train_df = pd.concat(train_dfs, ignore_index=True)
    val_df = pd.concat(val_dfs, ignore_index=True)
    test_df = pd.concat(test_dfs, ignore_index=True)
    return train_df, val_df, test_df

def copy_split(output_root, folder_name, files_df):
    print("Will write {} dataset".format(folder_name))
    filename = 'dataset.csv'
    dst = os.path.join(output_root, folder_name)
    # Create the destination folder if needed
    os.makedirs(dst, exist_ok=True)
    files_df.to_csv(os.path.join(dst, filename), index=False)


def create_datasets(in_dir, out_dir, val_size, test_size, seed):
    out_dir = make_dirs(in_dir, out_dir)
    full_dataset_path = os.path.join(in_dir, 'dataset.csv')
    full_labels_path = os.path.join(in_dir, 'labels.csv')
    dataset = read_data(full_dataset_path, full_labels_path)
    train, val, test = create_balanced_split(dataset, val_size, test_size, seed)
    print("Will create a {}-{}-{} train-val-test split".format(train.shape[0],
                                                               val.shape[0],
                                                               test.shape[0]))
    copy_split(out_dir, "train", train)
    copy_split(out_dir, "validation", val)
    copy_split(out_dir, "test", test)
