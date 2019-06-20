import argparse
from benchmark.dataset.data_preparation import preprocessing

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark application identification and "
                    "traffic classification based on raw packages")
    parser.add_argument("-p", "--pcapfiles", dest="pcapfiles",
                        type=str, required=True,
                        help="Folder with the pcaps to classify")
    parser.add_argument("-o", "--outputdir", dest="outputdir",
                        type=str, required=True,
                        help="Folder to sve the preprocessed files")


    args = parser.parse_args()
    root_pcap_files = args.pcapfiles
    out_dir = args.outputdir
    preprocessing(root_pcap_files, out_dir)