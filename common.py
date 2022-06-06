import boto3
import errno
import os

# 06/23/2019 - Adding new environment variable for Yara signature buckets and lib files.
# author: Abhinav Singh
# pre-update
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

import boto3
import errno
import os

YARA_RULES_S3_BUCKET = os.getenv("YARA_RULES_S3_BUCKET")
YARA_RULES_S3_PREFIX = os.getenv("YARA_RULES_S3_PREFIX", "yara_rules")
YARA_LIB_PATH = os.getenv("YARA_LIB_PATH", "./bin")
YARASCAN_PATH = os.getenv("YARASCAN_PATH", "./bin/yara")

s3 = boto3.resource('s3')
s3_client = boto3.client('s3')


def create_dir(path):
    if not os.path.exists(path):
        try:
            print("Attempting to create directory %s.\n" % path)
            os.makedirs(path)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
