import re


class DoubleChecker():

    REGEX_EVERYTHING_AFTER_SEMICOLUMN = "\:(.*)$"
    REGEX_EVERYTHING_AFTER_AT = "\@(.*)$"

    def __init__(self, parsed_file):
        """
        @parsed_file:
        """
        self.smtp_mail_from = parsed_file["authentication-results"]["spf"]["info"]["value"]
        self.dmarc_mail_from = parsed_file["authentication-results"]["dmarc"]["info"]["value"]
        self.header_from = parsed_file["from"]

    def match_regex(self, pattern, text):
        res_all = re.findall(pattern, text)
        res = "" if len(res_all) == 0 else res_all[0]
        return res

    def check_attack_server_a1(self):
        # Get the domain from the address
        addr_domain = self.match_regex(
            self.REGEX_EVERYTHING_AFTER_AT, self.full_mail_from)
        # Check the consistence between address domain and the
        # from value in header
        if addr_domain != self.header_from:
            return False
        else:
            return True

    def check_attack_server_a4(self):
        # Get the domain from the address
        addr_domain = self.match_regex(
            self.REGEX_EVERYTHING_AFTER_AT, self.full_mail_from)
        # Check the consistence between address domain and the
        # from value in header
        if addr_domain != self.header_from:
            return False
        else:
            return True

    def check_attack_server_a7(self):
        # Find the real address (i.e. getting rid of route part)
        real_addr = self.match_regex(
            self.REGEX_EVERYTHING_AFTER_SEMICOLUMN, self.full_mail_from)
        # print("real_addr:", real_addr)
        # Get the domain from the real address
        real_addr_domain = self.match_regex(
            self.REGEX_EVERYTHING_AFTER_AT, real_addr)
        # print("real_addr_domain:", real_addr_domain)
        # Check the consistence between real address domain and the
        # from value in header
        if real_addr_domain != self.header_from:
            return False
        else:
            return True

    def check_attack_server_a15(self):
        # Loop through each email address in domain header
        for address in self.header_from:
            # Filter all the domain address in from header
            domain = self.match_regex(
                self.REGEX_EVERYTHING_AFTER_AT, address)
            # If there is a domain, check if the domain is the same as it in smtp
            if domain and domain != self.smtp_mail_from:
                return False
        return True


    def check_attack_server_a16(self):
        # Loop through each email address in domain header
        for address in self.header_from:
            # Filter all the domain address in from header
            domain = self.match_regex(
                self.REGEX_EVERYTHING_AFTER_AT, address)
            # If there is a domain, check if the domain is the same as it in smtp
            if domain and domain != self.smtp_mail_from:
                return False
        return True


    def check_attack_server_a17(self):
        # Loop through each email address in domain header
        for address in self.header_from:
            # Filter all the domain address in from header
            domain = self.match_regex(
                self.REGEX_EVERYTHING_AFTER_AT, address)
            # If there is a domain, check if the domain is the same as it in smtp
            if domain and domain != self.smtp_mail_from:
                return False
        return True

    def check_attack_server_a18(self):
        # Loop through each email address in domain header
        for address in self.header_from:
            # Filter all the domain address in from header
            domain = self.match_regex(
                self.REGEX_EVERYTHING_AFTER_AT, address)
            # If there is a domain, check if the domain is the same as it in smtp
            if domain and domain != self.smtp_mail_from:
                return False
        return True


if __name__ == "__main__":
    dc = DoubleChecker({
        "content-length": "42",
        "x-email-client": "https://github.com/chenjj/espoofer",
        "message-id": "<1538085644648.096e3d4e-bc38-4027-b57e-FLIUSA@message-ids.testdomaintest.company>",
        "return-path": {
            "full_return_path": "any@testdomaintest.company",
            "return_path_wo_route_portion": "any@testdomaintest.company",
            "return_path_domain": "testdomaintest.company"
        },
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
        "date": "2020-11-24T04:16:34",
        "body": "Hi, this is a test message! Best wishes.",
        "to_domains": [
            "yahoo.com"
        ],
        "received-spf": "softfail (domain of transitioningtestdomaintest.company does not designate 24.114.51.127 as permitted sender)",
        "x-apparently-to": "cis6510victim@yahoo.com; Tue, 24 Nov 2020 04:16:40 +0000",
        "mime-version": "1.0",
        "timezone": "+0.0",
        "x-originating-ip": "[24.114.51.127]",
        "received": {
            "SMTP": {
                "from": "24.114.51.127 EHLO testdomaintest.company",
                "by": "10.217.136.93",
                "with": "SMTP",
                "date": "Tue, 24 Nov 2020 04:16:40 +0000",
                "hop": 1,
                "date_utc": "2020-11-24T04:16:40",
                "delay": 0
            },
            "HTTP": {
                "from": "10.217.136.93",
                "by": "atlas221.free.mail.ne1.yahoo.com",
                "with": "HTTP",
                "date": "Tue, 24 Nov 2020 04:16:40 +0000",
                "hop": 2,
                "date_utc": "2020-11-24T04:16:40",
                "delay": 0.0
            }
        },
        "x-ymailisg": "Uf1MQhsWLDvafG6p6Mp36WEqXyVTgaB7ZI7rnoFvc6wB7cJG\n nInqev1GPx_ql8r714b.hrnlvaldI21b7Id7hBQfcrsyIdXmVuuGxkp.0CQN\n 0NCVIgHLltrSXMM49_zwOdl4NgzbVTeT6ykZxvjfBvREuzg6NhKCGOeW0rdk\n rNjaTLtM7f2J4TvlbqKSnCYHqepKOWkUf2sosr3L8FK0izk4vskALKWGvXZK\n JFvZcNA1_EIBUeJ6i9dokQPInkLWYMeY7dWJnUqJ2eEBVkBjpngvdwRAD7rc\n d_v9HifDwjNFTMYXjzpkgmCJKE4fBFaIbBWMKNNQ7fNGo8RtRB_wnBlEgYYr\n hjecemiV089mnYZ0aOXkpRcKFsSLbZYjrBLPjDb3Hq.LK.GqyO0XuShcnn8P\n W.T4XsaChE2gsNuc6RcVTC1EJrg3CoEICSB4c92F4wKs.j1jc22q7jOSTohD\n 4DmU_hhQ0YJnxAzADFU9nWZ49vjW6wxc_AO1trYdbbl0FExaFlp0DKBjixB.\n 5HaGdQ7jmherYlta4QLXt_SR0tV8PJtncMgMtKoFG.X2WkTC_Y71dbTdLr.4\n 9qEOH4BmVmHYoarkA6wcJX14EWzTS4f8jRxGy9slGvAla_NyCdci4pHsVGIz\n Qd5UWKSWXRFysp6uHj7P2w90TsAg9Et4jjM6wA553b7BWUtohkzID6WYPt4x\n sh3GdSoUW6NPO39IyE6o35Pso9Uju6sxdLTZZWwZs6SV0H6pruLRLg0QeAAk\n Er_rjPAsr_7DXrSCv6KuDd_8PtHrLtiHccknKBi3ZM2.JRAJ2uTf.yEuee1e\n goGGFEnjvXidKCbceT74nEg94WGhpCfthQ4iyt8UHm4mnFFscbbRFy0zhFJQ\n bjdTA4Pa81kYQ2ft55cQ0X73BB0coxc4MKkWMGCT3gzQ.sENq89jswoBlWdf\n PTc.EQTigYH0RzWDCxxprtvseSfo971dk4XuSw--",
        "content-type": "text/plain; charset=\"UTF-8\"",
        "to": [
            "cis6510victim@yahoo.com"
        ],
        "subject": "A18: Specical characters precedence",
        "sender": "<s@sender.cibc.com>",
        "from": [
            "",
            "@testdomaintest.company",
            "security@cibc.com"
        ],
    })
    res = dc.check_attack_server_a18()
    print("res_a18:", res)
    # dc = DoubleChecker(
    #     "@cibc.com,@any.com:'any@testdomaintest.company", "security@cibc.com")
    # res = dc.check_attack_server_a7()
    # print("res:", res)
    # # Test for a15
    # dc = DoubleChecker(
    #     "testdomaintest.company", "?utf-8?B?PGFkbWluQGxlZ2l0aW1hdGUuY29tPg==?=,<second@testdomaintest.company>")
    # res = dc.check_attack_server_a15()
    # print("res_a15:", res)
    # # Test for a16
    # dc = DoubleChecker(
    #     "testdomaintest.company", "<@testdomaintest.company,@any.com:security@cibc.com>")
    # res = dc.check_attack_server_a16()
    # print("res_a16:", res)
    # # Test for a17
    # dc = DoubleChecker(
    #     "testdomaintest.company", "<security@cibc.com>\,<second@testdomaintest.company>")
    # res = dc.check_attack_server_a17()
    # print("res_a17:", res)
    # # Test for a18
    # dc = DoubleChecker(
    #     "testdomaintest.company", "security@cibc.com,<second@testdomaintest.company>")
    # res = dc.check_attack_server_a18()
    # print("res_a18:", res)
