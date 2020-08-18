# Cloud KMS Open Source Tools
This repository contains open source tools to be used with [Google Cloud Key 
Management Service][kms]. These tools are described below.

**This is not an officially supported Google product.**

## Cloud KMS OpenSSL Engine

This repository contains an [OpenSSL Engine][openssl-engine] that uses [Google 
Cloud KMS][kms] and [Google Cloud HSM][hsm] to perform cryptographic operations.

### Overview

An OpenSSL engine enables OpenSSL to delegate cryptographic operations to an 
alternative implementation while still allowing OpenSSL users to use the OpenSSL 
API. This allows applications that use OpenSSL to benefit from alternative 
cryptographic implementations without having to be modified.

Google Cloud KMS is a cloud-hosted key management service that lets users manage 
and use cryptographic keys for their cloud services the same way they do 
on-premises. Google Cloud HSM is a cloud-hosted hardware security module (HSM) 
service on Google Cloud Platform. With Cloud HSM, users can host encryption keys 
and perform cryptographic operations in FIPS 140-2 Level 3 certified HSMs.

The repository contains an OpenSSL engine that allows users to use Cloud KMS and 
Cloud HSM as a drop-in replacement for OpenSSL's default cryptography 
implementation. This allows, for example, an HTTPS web server that uses OpenSSL 
to make use of a private key that is protected by and never leaves an HSM 
running on Google Cloud Platform.

### Installation

Installation guide has been tested on a Debian GNU/Linux 9 distribution.

1. Set up a [Google Cloud service account][service-account] with the [`roles/cloudkms/signerVerifier`][roles] permission. Then, follow one of the authentication flows at ["Authenticating as a service account"][service-account] to authenticate your engine environment with the service account's credentials.

2. Install Git, Bazel, and the OpenSSL `libcrypto.so` libraries. On Debian, you can use the following commands:

    ```bash
    # Install Git and Bazel dependencies.
    sudo apt-get -y install git-all curl gnupg
    # Install Bazel.
    curl https://bazel.build/bazel-release.pub.gpg | sudo apt-key add -
    echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list
    sudo apt-get update && sudo apt-get -y install bazel
    # Install libcrypto.so.
    sudo apt-get -y install libssl-dev
    ```

3. Clone repository and build with Bazel.

    ```bash
    git clone https://github.com/googleinterns/cloud-kms-oss-tools.git
    cd cloud-kms-oss-tools/src
    bazel build ...
    ```

    The engine libraries are now located in `cloud-kms-oss-tools/bazel-bin/src/bridge/libengine.so` and `cloud-kms-oss-tools/bazel-bin/src/backing/libkms.so`.
    
    _Optional:_ Run all of the Bazel tests.
    
    ```bash
    bazel test ...
    ```
  
4. Add the engine to the OpenSSL configuration file, `openssl.cnf`. You can find the directory containing the OpenSSL configuration by running `openssl version -d`.

    ```bash
    $ openssl version -d
    OPENSSLDIR: "/usr/lib/ssl"
    $ sudo vim /usr/lib/ssl/openssl.cnf
    ```
    
    If `openssl.cnf` does not already define an `openssl_conf` section (some distributions will already define it), define it at the top-level of the configuration. For example, this line defines `openssl_conf` to point to the `openssl_init` section:
    
    ```
    openssl_conf = openssl_init
    ```

    At the bottom of the configuration file, add the `openssl_init` section and add the engine configuration for the `gcloudkms` engine:

    ```
    [ openssl_init ]
    engines = engine_section

    [ engine_section ]
    gcloudkms = gcloudkms_section

    [ gcloudkms_section ]
    dynamic_path = /my/path/to/bazel-bin/src/bridge/libengine.so  # Update as needed
    default_algorithms = ALL
    ```
    
5. Test that OpenSSL can find the engine by running `openssl engine`. `gcloudkms` should appear in the list.

    ```bash
    $ openssl engine
    (rdrand) Intel RDRAND engine
    (dynamic) Dynamic engine loading support
    (gcloudkms) Google Cloud KMS Engine
    ```
    
    Test that OpenSSL can dynamically load the engine by running `openssl engine -t gcloudkms`:
    
    ```bash
    $ openssl engine -t gcloudkms
    (gcloudkms) Google Cloud KMS Engine
         [ available ]
    ```
    
    If `available` appears, the engine is ready to be used.

[kms]: https://cloud.google.com/kms
[hsm]: https://cloud.google.com/hsm
[openssl-engine]: 
https://raw.githubusercontent.com/openssl/openssl/master/README.ENGINE
[service-account]:
https://cloud.google.com/docs/authentication/production
[roles]:
https://cloud.google.com/kms/docs/reference/permissions-and-roles#predefined
