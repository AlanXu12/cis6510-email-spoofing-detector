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
        self.dmarc_mail_from = parsed_file["authentication-results"]["dmarc"]["info"]["value"]
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
                # If there is a domain, check if the domain is the same as it in return path without mixed @
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
