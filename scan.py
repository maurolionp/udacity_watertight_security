# 06/23/2019 - Adding new feature to Scan uploaded files against set of Yara signatures uploaded on s3 bucket.
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
import yarascan
import copy
import json
from urllib.parse import unquote_plus
from common import *
from datetime import datetime
from distutils.util import strtobool
import sys
import os
from botocore.vendored import requests

ENV = os.getenv("ENV", "")
EVENT_SOURCE = os.getenv("EVENT_SOURCE", "S3")


def sns_start_scan(s3_object):
    print("Initial sns_start_scan")
    AV_SCAN_START_SNS_ARN = 'arn:aws:sns:us-east-1:302479247802:YaraScanNotification'
    message = s3_object
    sns_client = boto3.client("sns")
    sns_client.publish(
        TargetArn=AV_SCAN_START_SNS_ARN,
        Message=json.dumps({'default': json.dumps(message)}),
        MessageStructure="json"
    )


def sqs_start_scan(s3_object, scan_result_yara):
    SQS = boto3.client("sqs")
    queue_url = 'https://sqs.us-east-1.amazonaws.com/734507489904/YaraScanQueueItems.fifo'
    queue_name = 'YaraScanQueueItems'
    sqs_queue_url = SQS.get_queue_url(QueueName=queue_name)['QueueUrl']
    message = {
        "bucket": s3_object.bucket_name,
        "key": s3_object.key,
        "yara-scan": scan_result_yara
    }
    msg = SQS.send_message(QueueUrl=sqs_queue_url, MessageBody=(json.dumps(message)))


def event_object(event):
    if EVENT_SOURCE.upper() == "SNS":
        event = json.loads(event['Records'][0]['Sns']['Message'])
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = unquote_plus(event['Records'][0]['s3']['object']['key'])
    if (not bucket) or (not key):
        print("Unable to retrieve object from event.\n%s" % event)
        raise Exception("Unable to retrieve object from event.")
    return s3.Object(bucket, key)


def download_s3_object(s3_object, local_prefix):
    local_path = "%s/%s/%s" % (local_prefix, s3_object.bucket_name, s3_object.key)
    print("creating local path for file %s", local_path)
    create_dir(os.path.dirname(local_path))
    s3_object.download_file(local_path)
    return local_path


def delete_s3_object(s3_object):
    try:
        s3_object.delete()
    except:
        print("Failed to delete infected file: %s.%s" % (s3_object.bucket_name, s3_object.key))
    else:
        print("Infected file deleted: %s.%s" % (s3_object.bucket_name, s3_object.key))


def lambda_handler(event, context):
    start_time = datetime.utcnow()
    print("Script starting at %s\n" %
          (start_time.strftime("%Y/%m/%d %H:%M:%S UTC")))
    # print(event)
    s3_object = event_object(event)
    file_path = download_s3_object(s3_object, "/tmp")
    # print(file_path)
    print("file scanning to begin")
    # yarascan.update_sigs_from_s3(YARA_RULES_S3_BUCKET, YARA_RULES_S3_PREFIX)
    scan_result_yara = yarascan.scan_file(file_path)
    print(scan_result_yara)
    print("sending details to SQS Queue")
    sqs_start_scan(s3_object, scan_result_yara)


def str_to_bool(s):
    return bool(strtobool(str(s)))
