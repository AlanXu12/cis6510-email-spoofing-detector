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
        pass

    def check_attack_server_a16(self):
        pass

    def check_attack_server_a17(self):
        pass

    def check_attack_server_a18(self):
        pass


if __name__ == "__main__":
    dc = DoubleChecker(
        "@cibc.com,@any.com:'any@testdomaintest.company", "security@cibc.com")
    res = dc.check_attack_server_a7()

    print("res:", res)
