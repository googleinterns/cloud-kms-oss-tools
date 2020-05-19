# Cloud KMS Open Source Tools
This repository contains open source tools to be used with [Google Cloud Key 
Management Service][kms]. These tools are described below.

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

[kms]: https://cloud.google.com/kms
[hsm]: https://cloud.google.com/hsm
[openssl-engine]: 
https://raw.githubusercontent.com/openssl/openssl/master/README.ENGINE
