import sys
import argparse

from apis.sysinternals_vt import sysinternal_vt
from apis.hybrid_sandbox import hybrid_sandbox


__version__ = "1.0"
__description__ = "x-vriuSs: A tool for analyzing the performance of a file system"


def setup_args():
    parser = argparse.ArgumentParser(
        add_help=False,
        description=__description__,
        usage="%(prog)s [options] [value]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-x",
        action="store",
        nargs="+",
        dest="path",
        help="check detection ratio of file on VirusTotal",
        # default='terms'
    )

    # parser.add_argument(
    #     "-pecheck",
    #     action="store",
    #     dest="file",
    #     help="show file version, timestamp, and digital signature details",
    # )

    # parser.add_argument(
    #     "-hybrid",
    #     action="store",
    #     dest="hash",
    #     nargs="+",
    #     help="download sample malicious file from Hybrid Analysis",
    # )

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Add help message
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="show this help message and exit",
    )
    return parser


def main():
    optParser = setup_args()
    args = optParser.parse_args()
    # print(args.hash)
    if not (args.path): #or args.hash):
        optParser.print_help()
        return 0
    elif args.path:
        for i in range(0, len(args.path)):
            sysinternal_vt(args.path[i])
    # elif args.hash:
    #     # print(type(args.hash[0]))
    #     hybrid_sandbox(args.hash)
    else:
        pass


if __name__ == "__main__":
    sys.exit(main())
