import argparse
from benchmark.dataset.downsampling import down_sample

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark application identification and "
                    "traffic classification based on raw packages [dataset down sampling]")
    parser.add_argument("-i", "--inputdir", dest="inputdir",
                        type=str, required=True,
                        help="Folder with the raw packets already processed")
    parser.add_argument("-o", "--outputdir", dest="outputdir",
                        type=str, required=True,
                        help="Folder to save the down sampled dataset")


    # TODO: add more arguments, for example task, app id or traffic classification
    args = parser.parse_args()
    input_dir = args.inputdir
    output_dir = args.outputdir
    down_sample(input_dir, output_dir)
