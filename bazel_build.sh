#!/bin/bash
# Fail on any error.
set -e
# Treat unset variables an error.
set -u
# Print commands as executed.
set -x

apt-get update

# Install a system-wide OpenSSL headers.
apt-get -y install libssl-dev

apt-get -y install  software-properties-common
add-apt-repository ppa:git-core/ppa
apt-get -y update
apt-get -y install git

apt-get -y install \
  apt-transport-https \
  curl \
  gnupg2 \
  ca-certificates \
  openjdk-8-jdk
echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list
curl https://bazel.build/bazel-release.pub.gpg | apt-key add - 
apt-get update
apt-get -y install bazel
apt-get -y upgrade bazel

bazel test ... \
  --verbose_failures=true \
  --test_output=errors \

exit 0
