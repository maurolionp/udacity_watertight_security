#!/usr/bin/env bash
# 06/23/2019 - Adding new feature that creates Yara scanning lambda fucntion
#author: Abhinav Singh

lambda_output_file=/opt/app/build/lambda.zip

set -e

yum update -y
yum install -y cpio python3-pip yum-utils zip
yum -y install gcc openssl-devel bzip2-devel libffi-devel
yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum install -y python3-devel.x86_64

pip3 install --no-cache-dir virtualenv


virtualenv env
. env/bin/activate
pip3 install --no-cache-dir -r requirements.txt

pushd /tmp
yumdownloader -x \*i686 --archlist=x86_64 json-c pcre2 bzip2-libs gnutls nettle

rpm2cpio json-c*.rpm | cpio -idmv
rpm2cpio pcre*.rpm | cpio -idmv
rpm2cpio bzip2-libs-*.rpm | cpio -idmv
rpm2cpio gnutls-*.rpm | cpio -idmv
rpm2cpio *.rpm | cpio -idmv

popd
mkdir -p bin
cp /tmp/usr/lib64/* bin/.
mkdir -p build
zip -r9 $lambda_output_file *.py bin
zip -r9 $lambda_output_file yara-rules/
cd env/lib/python3.7/site-packages
zip -r9 $lambda_output_file *