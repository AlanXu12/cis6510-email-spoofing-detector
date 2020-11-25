import argparse


if __name__ == '__main__':
    example_text = '''usage:
      python antiespoofer.py -i server_a1.txt
      python antiespoofer.py --input server_a1.txt'''

    parser = argparse.ArgumentParser(description='Detect raw emails.',
                                     epilog=example_text,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-i', '--input', type=argparse.FileType('r'),
                        help='input file name <input_file>', required=True)

    args = parser.parse_args()
