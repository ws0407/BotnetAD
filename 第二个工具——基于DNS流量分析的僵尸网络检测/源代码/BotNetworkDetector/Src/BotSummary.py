import sys
import csv


class BotSummary:
    def __init__(self, filename):
        self.filename = filename
        self.counter = 1
        tmp_out_file = filename.split(".")
        self.outfile = open(tmp_out_file[0] + "_out.csv", "w")
        self.bot_count = 0
        self.clean_count = 1
        self.prev_token = ""
        self.month = 0
        self.day = 0
        self.hour = 0
        self.tmpstr = ""
        self.bot_ip = ""

    def parse_file(self):
        req_infile = open(self.filename, "r")
        # req_infile = open("sample\\request.csv", "r")
        req_reader = csv.reader(req_infile, delimiter=',')
        count = 1
        for res in req_reader:
            try:
                if count == 1:
                    count += 1
                    continue
                if count == 15000000:
                    break
                self.read_record(res)
                count += 1

            except:
                print ("Error reading CSV record " + str(count), sys.exc_info())
                continue
        print(self.bot_ip)
        print (self.tmpstr)

        self.outfile.close()

    def read_record(self, res):
        try:
            # print(res[25])

            token = res[2].split("_")
            month = token[1].strip()[0:2]
            day = token[1].strip()[2:4]
            hour = token[1].strip()[4:6]

            if (month != self.month):
                self.tmpstr += "\nMonth  : " + str(month)

            if (day != self.day):
                self.tmpstr += "\n\tDay  " + str(day) + ","

            if (hour == self.hour):
                if res[25].strip() == "Bot":
                    if self.bot_ip[len(self.bot_ip) - 1] == "\n":
                        self.bot_ip += str(day) + " " + str(hour) + " " + token[0]
                    else:
                        self.bot_ip += " " + token[0]
                    self.bot_count += 1
                else:
                    self.clean_count += 1
            else:
                self.bot_ip += "\n"
                self.tmpstr += str(self.bot_count) + ","
                self.clean_count = 0
                self.bot_count = 0
                if res[25].strip() == "Bot":
                    self.bot_count = 1
                else:
                    self.clean_count = 1

            self.counter += 1
            self.prev_token = token[1]
            self.month = month
            self.day = day
            self.hour = hour

            # print tmp_str
        except:
            print ("Error in read_record ", sys.exc_info())


# //testcase():
obj = BotSummary("../Output/DNS_FP_out.csv")
obj.parse_file()
