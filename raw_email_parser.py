import mailparser
import json
import re


class RawEmailParser():

    REGEX_EMAIL_CHECKER_TEMPLATE = "(?<={}=)(.*)(?=;)"
    REGEX_HELO_DOMAIN = "(?<=helo.)(.*)$"
    REGEX_FULL_RETURN_PATH = "(?<=<)(.*)(?=>)"
    REGEX_RETURN_PATH_WITHOUT_ROUTE_PORTION = "(?<=:)(.*)(?=>)"
    REGEX_RETURN_PATH_DOMAIN = "(?<=@)(.*)$"

    def __init__(self, input_file_path):
        self.input_file_path = input_file_path

    def parse(self):
        # Initally parse the input file and put result into dict
        mail = mailparser.parse_from_file(self.input_file_path)
        parsed_mail_init_str = mail.mail_json
        parsed_mail_init = json.loads(parsed_mail_init_str)

        # Modify the init parse result to meet usage requirements
        parsed_mail_final = self.__modify_parsed_res(parsed_mail_init)
        return parsed_mail_final

    def __match_regex(self, pattern, text):
        res_all = re.findall(pattern, text)
        res = "" if len(res_all) == 0 else res_all[0]
        return res

    def __modify_parsed_res(self, parsed_mail_init):
        parsed_mail_final = parsed_mail_init.copy()
        # Modify Authentication-Results
        parsed_mail_final["authentication-results"] = self.__modify_auth_res(
            parsed_mail_init["authentication-results"])

        # Modify From in header
        parsed_mail_final["from"] = self.__modify_header_from(
            parsed_mail_init["from"])

        # Modify To in header
        parsed_mail_final["to"] = self.__modify_header_to(
            parsed_mail_init["to"])

        # Modify Received
        parsed_mail_final["received"] = self.__modify_received(
            parsed_mail_init["received"])

        # Modify Return Path
        parsed_mail_final["return-path"] = self.__modify_return_path(
            parsed_mail_init["return-path"])

        return parsed_mail_final

    def __modify_auth_res(self, auth_res_org):
        # Get testing result records for DKIM, SPF, and DMARC
        dkim_res = self.__match_regex(
            self.REGEX_EMAIL_CHECKER_TEMPLATE.format("dkim"), auth_res_org)
        spf_res = self.__match_regex(
            self.REGEX_EMAIL_CHECKER_TEMPLATE.format("spf"), auth_res_org)
        dmarc_res = self.__match_regex(
            self.REGEX_EMAIL_CHECKER_TEMPLATE.format("dmarc"), auth_res_org)

        # Re-format the testing result records of DKIM, SPF, and DMARC
        auth_res_updated = {"dkim": dict(), "spf": dict(), "dmarc": dict()}
        if dkim_res:
            dkim_res_lst = dkim_res.split(" ")
            auth_res_updated["dkim"]["result"] = dkim_res_lst[0]
            if len(dkim_res_lst) == 2:
                auth_res_updated["dkim"]["info"] = dkim_res_lst[1]
        if spf_res:
            spf_res_lst = spf_res.split(" ")
            auth_res_updated["spf"]["result"] = spf_res_lst[0]
            if len(spf_res_lst) == 2:
                auth_res_updated["spf"]["info"] = spf_res_lst[1]
        if dmarc_res:
            dmarc_res_lst = dmarc_res.split(" ")
            auth_res_updated["dmarc"]["result"] = dmarc_res_lst[0]
            if len(dmarc_res_lst) == 2:
                auth_res_updated["dmarc"]["info"] = dmarc_res_lst[1]

        return auth_res_updated

    def __modify_header_from(self, header_from_org):
        header_from_final = []
        # Simply destroy the outter list for each record is
        # sufficient for re-formating
        for next_from in header_from_org:
            header_from_final.append(next_from[1])
        return header_from_final

    def __modify_header_to(self, header_to_org):
        header_to_final = []
        # Simply destroy the outter list for each record is
        # sufficient for re-formating
        for next_to in header_to_org:
            header_to_final.append(next_to[1])
        return header_to_final

    def __modify_received(self, received_org):
        received_final = {"SMTP": {}, "HTTP": {}}
        for next_received in received_org:
            # SMTP is the received record for HELO
            if next_received["with"] == "SMTP":
                next_received_final = next_received.copy()
                next_received_final["from"] = dict()
                full_ehlo_org = next_received["from"]
                ehlo_domain = self.__match_regex(
                    self.REGEX_HELO_DOMAIN, next_received["from"])
                next_received_final["from"]["full_ehlo"] = full_ehlo_org
                next_received_final["from"]["domain"] = ehlo_domain
                received_final["SMTP"] = next_received_final
            # HTTP is the received record for fetching the email
            # from Yahoo receiving server
            elif next_received["with"] == "HTTP":
                received_final["HTTP"] = next_received
        return received_final

    def __modify_return_path(self, return_path_org):
        full_return_path = self.__match_regex(
            self.REGEX_FULL_RETURN_PATH, return_path_org)
        return_path_without_route_portion = self.__match_regex(
            self.REGEX_RETURN_PATH_WITHOUT_ROUTE_PORTION, return_path_org)
        # In case return path has route portion, find the real address
        if return_path_without_route_portion == "":
            return_path_without_route_portion = full_return_path
            return_path_domain = self.__match_regex(
                self.REGEX_RETURN_PATH_DOMAIN,
                return_path_without_route_portion)
        else:
            return_path_domain = self.__match_regex(
                self.REGEX_RETURN_PATH_DOMAIN,
                return_path_without_route_portion)
        return_path_final = dict()
        return_path_final["full_return_path"] = full_return_path
        return_path_final["return_path_wo_route_portion"] = return_path_without_route_portion
        return_path_final["return_path_domain"] = return_path_domain
        return return_path_final


if __name__ == "__main__":
    for i in [1, 4, 7, 15, 16, 17, 18]:
        fn = "server_a{}.txt".format(str(i))
        rep = RawEmailParser("./attack_input/" + fn)
        rep_res = rep.parse()
        print("\n----------------" + fn + "-------------------------")
        print(json.dumps(rep_res, indent=4))
        print("------------------------------------------------\n")

    # file_path = "./attack_input/server_a15.txt"
    # mail = mailparser.parse_from_file(file_path)
    # parsed_mail_str = mail.mail_json
    # parsed_mail = json.loads(parsed_mail_str)

    # print(mail.body)
    # print(mail.date)
    # print(mail.mail_json)
    # print(type(mail.mail_json))
    # print(parsed_mail)
    # print(type(parsed_mail))
