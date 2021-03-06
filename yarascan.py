# 06/23/2019 - Adding new feature to update bucket containing Rara rules for scanning.
# author: Abhinav Singh

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import os
import pwd
import re
from common import *
from subprocess import check_output, Popen, PIPE, STDOUT
import yara
import logging
import boto3


def current_library_search_path():
    ld_verbose = check_output(["ld", "--verbose"]).decode('utf-8')
    rd_ld = re.compile("SEARCH_DIR\(\"([A-z0-9/-]*)\"\)")
    return rd_ld.findall(ld_verbose)


def scan_file(path):
    pwd = os.getcwd()
    print(pwd)
    YARA_DEFINITION_PATH = pwd + '/yara-rules'
    print(YARA_DEFINITION_PATH)
    file_list = []
    rule_name_list = []
    yara_scan_info = {
        "scan_performed": "No",
        "scan_result": "Not-detected",
        "detection_rule": "N/A"
    }
    yara_env = os.environ.copy()
    yara_env["LD_LIBRARY_PATH"] = YARA_LIB_PATH
    # print(yara_env)
    file = open(path, 'rb')  # open file for yara scanning
    # print (file)
    file_data = file.read()
    try:
        for (dirpath, dirnames, filenames) in os.walk(YARA_DEFINITION_PATH):
            # print(dirnames)
            file_list.extend(filenames)
            print(file_list)
        for item in file_list:
            # print (file_list)
            rule = yara.compile(filepath=YARA_DEFINITION_PATH + '/' + str(item))
            matches = rule.match(data=file_data)
            logging.info(matches)
            if matches:
                rule_name_list.append(matches[0].rule)
                yara_scan_info['scan_performed'] = "Yes"
                yara_scan_info['scan_result'] = "Detected"
                yara_scan_info['detection_rule'] = rule_name_list
        print(yara_scan_info)
        return yara_scan_info
    except Exception as e:
        print(e)


def main():
    path = input("Enter the path of your file: ")
    scan_file(path)


if __name__ == "__main__":
    main()
