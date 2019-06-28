import argparse
from bbudget.dataset.split_dataset import create_datasets

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script to create train-val-test splits from an already preprocessed dataset")
    parser.add_argument("-i", "--inputdir", dest="inputdir",
                        type=str, required=True,
                        help="Folder with the raw packets already processed and downsampled")
    parser.add_argument("-o", "--outputdir", dest="outputdir",
                        type=str, required=True,
                        help="Folder to save the split dataset")
    parser.add_argument("-v", "--validationsize", dest="val_size", type=float,
                        help="Relative validation set size", default=0.1)
    parser.add_argument("-t", "--testset", dest="test_size", type=float,
                        help="Relative test set size", default=0.1)
    parser.add_argument("-s", "--seed", dest="seed", type=int,
                        help="Random seed", default=None)


    args = parser.parse_args()
    input_dir = args.inputdir
    output_dir = args.outputdir
    val_size = args.val_size
    test_size = args.test_size
    seed = args.seed

    create_datasets(input_dir, output_dir, val_size, test_size, seed)
