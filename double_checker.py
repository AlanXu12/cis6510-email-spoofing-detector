import re
import base64


class DoubleChecker():

    REGEX_EVERYTHING_AFTER_COLUMN = "\:(.*)$"
    REGEX_EVERYTHING_AFTER_AT = "\@(.*)$"
    REGEX_EVERYTHING_BETWEEN_CHEVRON = "\<(.*?)\>"
    REGEX_EVERY_EMAIL_ADDRESS = "([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)"
    REGEX_EVERYTHING_UTF_8 = "(?<==\?utf-8\?B\?)(.*)(?=\?=)"
    
    NON_SUSPECIOUS_MSG = "Not a suspecious email."
    SUSPECIOUS_MSG_TMP = "This email is detected to be suspecious for:\n\t- Attack server_a{} in espoofer attacking tool\n\t- i.e. Attack A{} in the paper"

    def __init__(self, parsed_file):
        """
        @parsed_file:
        """
        self.smtp_mail_from = parsed_file["authentication-results"]["spf"]["info"]["value"]
        # self.dmarc_mail_from = parsed_file["authentication-results"]["dmarc"]["info"]["value"]
        self.header_from = parsed_file["from"]
        self.return_path_domain = parsed_file["return-path"]["return_path_domain"]


    def match_regex(self, pattern, text):
        res_all = re.findall(pattern, text)
        return res_all

    def check_attack_server_a1(self):
        # Filter all the email address in from header
        header_from_list = self.match_regex(
            self.REGEX_EVERYTHING_BETWEEN_CHEVRON, self.header_from)
        # Check if the from header is empty
        if len(header_from_list) != 0:
            # Loop through each email address in domain header
            for address in header_from_list:
                # Filter all the domain address in from header
                domain = self.match_regex(
                    self.REGEX_EVERYTHING_AFTER_AT, address)
                # If there is a domain, check if the domain is the same as it in smtp
                if len(domain) == 0 or domain[0] != self.smtp_mail_from:
                    return self.SUSPECIOUS_MSG_TMP.format("1", "1")
        else:
            return self.SUSPECIOUS_MSG_TMP.format("1", "1")
        return self.NON_SUSPECIOUS_MSG

    def check_attack_server_a4(self):
        # Filter all the email address in from header
        header_from_list = self.match_regex(
            self.REGEX_EVERYTHING_BETWEEN_CHEVRON, self.header_from)
        # Check if the from header is empty
        if len(header_from_list) != 0:
            # Loop through each email address in domain header
            for address in header_from_list:
                # Filter all the domain address in from header
                domain = self.match_regex(
                    self.REGEX_EVERYTHING_AFTER_AT, address)
                # If there is a domain, check if the domain is the same as it in smtp
                if len(domain) == 0 or domain[0] != self.smtp_mail_from:
                    return self.SUSPECIOUS_MSG_TMP.format("4", "4")
        else:
            return self.SUSPECIOUS_MSG_TMP.format("4", "4")
        return self.NON_SUSPECIOUS_MSG

    def check_attack_server_a7(self):
        # Filter all the email address in from header
        header_from_list = self.match_regex(
            self.REGEX_EVERYTHING_BETWEEN_CHEVRON, self.header_from)
        # Check if the from header is empty
        if len(header_from_list) != 0:
            # Loop through each email address in domain header
            for address in header_from_list:
                # Filter all the domain address in from header
                domain = self.match_regex(
                    self.REGEX_EVERYTHING_AFTER_AT, address)
                # If there is a domain, check if the domain is the same as it in return path without route portion
                if len(domain) == 0 or domain[0] != self.return_path_domain:
                    return self.SUSPECIOUS_MSG_TMP.format("7", "5")
        else:
            return self.SUSPECIOUS_MSG_TMP.format("7", "5")
        return self.NON_SUSPECIOUS_MSG

    def check_attack_server_a15(self):
        # Filter all the email address within <> in from header
        header_from_list = self.match_regex(
            self.REGEX_EVERYTHING_BETWEEN_CHEVRON, self.header_from)
        encoded_header_from_list = self.match_regex(
            self.REGEX_EVERYTHING_UTF_8, self.header_from)
        if len(encoded_header_from_list) != 0:
            for encoded_address in encoded_header_from_list:
                encoded_address_bs64 = encoded_address.encode('utf-8')
                decoded_address_bs64 = base64.b64decode(encoded_address_bs64)
                decoded_address = decoded_address_bs64.decode('utf-8')
                decoded_address_list = self.match_regex(
                    self.REGEX_EVERYTHING_BETWEEN_CHEVRON, decoded_address)
                header_from_list = header_from_list + decoded_address_list
            # Check if the from header is empty
        if len(header_from_list) != 0:
            # Loop through each email address in domain header
            for address in header_from_list:
                # Filter all the domain address in from header
                domain = self.match_regex(
                    self.REGEX_EVERYTHING_AFTER_AT, address)
                # If there is a domain, check if the domain is the same as it in smtp
                if len(domain) == 0 or domain[0] != self.smtp_mail_from:
                    return self.SUSPECIOUS_MSG_TMP.format("15", "10")
        else:
            return self.SUSPECIOUS_MSG_TMP.format("15", "10")
        return self.NON_SUSPECIOUS_MSG


    def check_attack_server_a16(self):
        # Filter all the email address with route portion in from header
        header_from_list_with_rp = self.match_regex(
            self.REGEX_EVERYTHING_BETWEEN_CHEVRON, self.header_from)
        # Filter all the email address in from header
        header_from_list = self.match_regex(
            self.REGEX_EVERYTHING_AFTER_COLUMN, header_from_list_with_rp[0])
        # Check if the from header is empty
        if len(header_from_list) != 0:
            # Loop through each email address in domain header
            for address in header_from_list:
                # Filter all the domain address in from header
                domain = self.match_regex(
                    self.REGEX_EVERYTHING_AFTER_AT, address)
                # If there is a domain, check if the domain is the same as it in smtp
                if len(domain) == 0 or domain[0] != self.smtp_mail_from:
                    return self.SUSPECIOUS_MSG_TMP.format("16", "11")
        else:
            return self.SUSPECIOUS_MSG_TMP.format("16", "11")
        return self.NON_SUSPECIOUS_MSG


    def check_attack_server_a17(self):
        # Filter all the email address in from header
        header_from_list = self.match_regex(
            self.REGEX_EVERYTHING_BETWEEN_CHEVRON, self.header_from)
        # Check if the from header is empty
        if len(header_from_list) != 0:
            # Loop through each email address in domain header
            for address in header_from_list:
                # Filter all the domain address in from header
                domain = self.match_regex(
                    self.REGEX_EVERYTHING_AFTER_AT, address)
                # If there is a domain, check if the domain is the same as it in smtp
                if len(domain) == 0 or domain[0] != self.smtp_mail_from:
                    return self.SUSPECIOUS_MSG_TMP.format("17", "12")
        else:
            return self.SUSPECIOUS_MSG_TMP.format("17", "12")
        return self.NON_SUSPECIOUS_MSG

    def check_attack_server_a18(self):
        # Filter all the email address in from header
        header_from_list = self.match_regex(
            self.REGEX_EVERY_EMAIL_ADDRESS, self.header_from)
        # Check if the from header is empty
        if len(header_from_list) != 0:
            # Loop through each email address in domain header
            for address in header_from_list:
                # Filter all the domain address in from header
                domain = self.match_regex(
                    self.REGEX_EVERYTHING_AFTER_AT, address)
                # If there is a domain, check if the domain is the same as it in smtp
                if len(domain) == 0 or domain[0] != self.smtp_mail_from:
                    return self.SUSPECIOUS_MSG_TMP.format("18", "13")
        else:
            return self.SUSPECIOUS_MSG_TMP.format("18", "13")
        return self.NON_SUSPECIOUS_MSG


if __name__ == "__main__":
    dc = DoubleChecker({
        "from": " <security@cibc.com>",
        "mime-version": "1.0",
        "x-apparently-to": "cis6510victim@yahoo.com; Tue, 24 Nov 2020 04:08:50 +0000",
        "timezone": "+0.0",
        "body": "Hi, this is a test message! Best wishes.",
        "return-path": {
            "full_return_path": "@cibc.com,@any.com:'any@testdomaintest.company",
            "return_path_wo_route_portion": "'any@testdomaintest.company",
            "return_path_domain": "testdomaintest.company"
        },
        "subject": "A7: routing address in mailfrom",
        "x-ymailisg": "r0mTy2cWLDt3nc7aldhV2bLmHgriCQQIO8XM54jzV34SAa2l\n dH4FXaS0g5kX2Oloh3caSpxzOuJYeep3NjAVo_QpaZ4JS4wW08b8TEVZXbnu\n Ji9wBRfmsyIEoOfE2dhMGlo56dsZVlZ8wu7QuURRUHTpjd4qfHcfoJI13v.a\n AtoBDKrGbYypulIm596M1ogva2N2JQBB1ObZxVZuz_fFdketSP2wcXIqmsb7\n PLAVFzOBdfEKTUycM94lmBWnUnDaPP2Nc43IeRXGVd06BlelyVMBEsyhd8pG\n I9fxs4tti98hym7sNMnJS_vDvz8yRoZ0VQemZAoPU4MEej43qoZdl0xfQx66\n cX8elCOeaqKcaHYpSvPpbXkWLI7ntZKYc_c2BySG4p1Cr1DIe64hvUJaYi.U\n kb8IRt4hyHzS16r5ufvZQ1QwvSrPd4aO5iqnnid4lla9z5qbkUaCRVTzQ87Q\n tj2ZsIFNyiVaKLIkBqB60dJq5bqmN1v1AUQQpGOvQDvm1.Fqy308XRcHJvFc\n DaVXfvfn.EY6E8g4hVQHx_9DaeNEcMo5kyyIUd2W1YJg6duTVAmvQ.TzBEx8\n V.m7wYA6nXeCAbzGRJcj2U8TIDGA46cQ3nBWhA5e6mGbDp1Lozrli4dJEtTj\n Uuv1mqoyUDqkJDv1VEE5P6mHtAti_WJgW9gz7XJId5DVLg7fVKXoxRxhG4Oz\n rXJQh_TEp4SbS9pnlurr62S7_6JiLpVvMN8QrjjO4sxCRxSVRIPunKcoSIK5\n ocWioOBt2JYfBdns6hN16ZXm7y85QZUnEhSVUYjGLOo88vYKwwElyqfO9VEj\n ujHJCMmCeuj1waHn89zqREv_W.k.o6pWkQKngVXcwoA3YtmXTj6XOZ3yODll\n iEbnApnbaH1qFjSgv62zm6BgDYhT9B84qfH5fy1Lscai9uPpC5Pfj_sVL8NH\n MA--",
        "authentication-results": {
            "dkim": {
                "result": "unknown"
            },
            "spf": {
                "result": "softfail",
                "info": {
                    "field": "smtp.mailfrom",
                    "value": "testdomaintest.company"
                }
            },
            "dmarc": {
                "result": "success(p=NONE)",
                "info": {
                    "field": "header.from",
                    "value": "cibc.com"
                }
            }
        },
        "content-length": "42",
        "message-id": "<1538085644648.096e3d4e-bc38-4027-b57e-3HZD0O@message-ids.testdomaintest.company>",
        "x-originating-ip": "[24.114.51.143]",
        "date": "2020-11-24T04:08:44",
        "to_domains": [
            "yahoo.com"
        ],
        "to": [
            "cis6510victim@yahoo.com"
        ],
        "received": {
            "SMTP": {
                "from": "24.114.51.143 EHLO testdomaintest.company",
                "by": "10.197.39.106",
                "with": "SMTP",
                "date": "Tue, 24 Nov 2020 04:08:50 +0000",
                "hop": 1,
                "date_utc": "2020-11-24T04:08:50",
                "delay": 0
            },
            "HTTP": {
                "from": "10.197.39.106",
                "by": "atlas104.free.mail.bf1.yahoo.com",
                "with": "HTTP",
                "date": "Tue, 24 Nov 2020 04:08:50 +0000",
                "hop": 2,
                "date_utc": "2020-11-24T04:08:50",
                "delay": 0.0
            }
        },
        "content-type": "text/plain; charset=\"UTF-8\"",
        "x-email-client": "https://github.com/chenjj/espoofer",
        "received-spf": "softfail (domain of transitioningtestdomaintest.company does not designate 24.114.51.143 as permitted sender)"
    })
    res = dc.check_attack_server_a7()
    print("res_a7:", res)
