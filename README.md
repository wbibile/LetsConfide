# LetsConfide 
LetsConfide is a library that helps software secure and manage secret information such as database credentials. 
The current implementation is in Java however, the underlying algorithms and data structures are language independent.  

## Features
* Input and manage secret information using YAML 
* Cryptography backed by a TPM 2.0 module
* Use of hardware root of trust to seal encryption keys
* Ability to configure ciphers and root of trust used by the TPM 

## Requirements
* Requires a JDK 8 compatible development environment at compile time  
* A TPM 2.0 module and a Java 8 compatible JRE must be available at runtime. 

## Getting Started 
Please refer to the example provided in the wiki [Securing Database Credentials](../../wiki/Overview-of-Operation#example-securing-database-credentials) to get started. 
