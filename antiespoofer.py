import argparse
from raw_email_parser import RawEmailParser
from double_checker import DoubleChecker


def anti_espoofer_check(input_file):
    rep = RawEmailParser(input_file)
    rep_res = rep.parse()
    dc = DoubleChecker(rep_res)
    dkim_res = rep_res["authentication-results"]["dkim"]["result"]
    spf_res = rep_res["authentication-results"]["spf"]["result"]
    dmarc_res = rep_res["authentication-results"]["dmarc"]["result"]

    # print("dkim_res:", dkim_res)
    # print("spf_res:", spf_res)
    # print("dmarc_res:", dmarc_res)

    res = None
    # server_a1
    if dkim_res == "unknown" and spf_res == "none" and "success" in dmarc_res:
        res = dc.check_attack_server_a1()
    # server_a4
    elif (dkim_res == "perm_fail" and spf_res == "softfail" and
          "success" in dmarc_res):
        res = dc.check_attack_server_a4()
    # server_a15
    elif (dkim_res == "unknown" and spf_res == "softfail" and
          dmarc_res == "unknown"):
        res = dc.check_attack_server_a15()
    elif (dkim_res == "unknown" and spf_res == "softfail" and
          "success" in dmarc_res):
        # Having route portion in Return Path of parsing result
        has_route_in_rp = rep_res["return-path"]["full_return_path"] != rep_res["return-path"]["return_path_wo_route_portion"]
        # Having route portion in From in header of parsing result
        has_route_in_hf = ":" in rep_res["from"]
        # Containing backslash in From in header of parsing result
        has_backslash_in_hf = "\\" in rep_res["from"]
        # Not starting with "<" in From in header of parsing result
        starts_with_less_than_hf = rep_res["from"].startswith("<")
        # server_a7
        if has_route_in_rp:
            res = dc.check_attack_server_a7()
        # server_a16
        elif has_route_in_hf:
            res = dc.check_attack_server_a16()
        # server_a17
        elif has_backslash_in_hf:
            res = dc.check_attack_server_a17()
        # server_a18
        elif not starts_with_less_than_hf:
            res = dc.check_attack_server_a18()
    return res


if __name__ == '__main__':
    example_text = '''usage:
      python antiespoofer.py -i server_a1.txt
      python antiespoofer.py --input server_a1.txt'''

    parser = argparse.ArgumentParser(description='Detect raw emails.',
                                     epilog=example_text,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-i', '--input', action='store', dest='input',
                        help='input file full path <input_file_full_path>',
                        required=True)

    args = parser.parse_args()
    input_file = args.input
    double_check_res = anti_espoofer_check(input_file)
    print("Raw email file: \n\t{} \nDouble check result: \n\t{}".format(input_file, double_check_res))
