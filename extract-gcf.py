
import argparse
import os.path

from pysteam.fs.cachefile import CacheFile


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract files from a Steam cache")
    parser.add_argument("cachefile", help="Path to the cache file to extract")
    parser.add_argument(
        "-m",
        "--minimum",
        action="store_true",
        help="Extract minimum footprint only",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output directory for extraction",
    )
    args = parser.parse_args()

    cache_file = CacheFile.parse(args.cachefile)
    output_dir = os.path.realpath(args.output)
    if args.minimum:
        cache_file.extract_minimum_footprint(output_dir)
    else:
        cache_file.extract(output_dir)


if __name__ == "__main__":
    main()
