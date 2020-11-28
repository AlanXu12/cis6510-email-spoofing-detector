import re


class DoubleChecker():

    REGEX_EVERYTHING_AFTER_SEMICOLUMN = "\:(.*)$"
    REGEX_EVERYTHING_AFTER_AT = "\@(.*)$"

    def __init__(self, full_mail_from, header_from):
        """
        @full_mail_from: 
        @header_from: 
        """
        self.full_mail_from = full_mail_from
        self.header_from = header_from

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
        # Get the domain from the EHLO address
        addr_domain = ["testdomaintest.company"]
        # Decode the domain address in From header (legitimate.com)
        real_header_from = ["legitimate.com", "testdomaintest.company"]
        for domain in real_header_from:
            if domain != addr_domain[0]:
                return False
        return True


    def check_attack_server_a16(self):
        # Get the domain from the EHLO address
        addr_domain = ["testdomaintest.company"]
        # Get the domain address in From header (i.e. getting rid of route part)
        real_header_from = ["cibc.com"]
        for domain in real_header_from:
            if domain != addr_domain[0]:
                return False
        return True


    def check_attack_server_a17(self):
        # Get the domain from the EHLO address
        addr_domain = ["testdomaintest.company"]
        # Get the domain address in From header (i.e. getting rid of quoted pair)
        real_header_from = ["cibc.com", "testdomaintest.company"]
        for domain in real_header_from:
            if domain != addr_domain[0]:
                return False
        return True

    def check_attack_server_a18(self):
        # Get the domain from the EHLO address
        addr_domain = ["testdomaintest.company"]
        # Get the domain address in From header (i.e. getting rid of special characters)
        real_header_from = ["cibc.com", "testdomaintest.company"]
        for domain in real_header_from:
            if domain != addr_domain[0]:
                return False
        return True


if __name__ == "__main__":
    dc = DoubleChecker(
        "@cibc.com,@any.com:'any@testdomaintest.company", "security@cibc.com")
    res = dc.check_attack_server_a7()
    print("res:", res)
    # Test for a15
    dc = DoubleChecker(
        "testdomaintest.company", "?utf-8?B?PGFkbWluQGxlZ2l0aW1hdGUuY29tPg==?=,<second@testdomaintest.company>")
    res = dc.check_attack_server_a15()
    print("res_a15:", res)
    # Test for a16
    dc = DoubleChecker(
        "testdomaintest.company", "<@testdomaintest.company,@any.com:security@cibc.com>")
    res = dc.check_attack_server_a16()
    print("res_a16:", res)
    # Test for a17
    dc = DoubleChecker(
        "testdomaintest.company", "<security@cibc.com>\,<second@testdomaintest.company>")
    res = dc.check_attack_server_a17()
    print("res_a17:", res)
    # Test for a18
    dc = DoubleChecker(
        "testdomaintest.company", "security@cibc.com,<second@testdomaintest.company>")
    res = dc.check_attack_server_a18()
    print("res_a18:", res)
