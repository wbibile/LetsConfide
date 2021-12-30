# LetsConfide 
LetsConfide is a library for securing and managing secret information such as database credentials used by software. 
The current implementation is in Java however, the underlying algorithms and data structures selected are language independent.  

## Features
* Input and manage secret information using YAML 
* Encryption keys are backed by a TPM 2.0 module
* TPM storage keys are authenticated using RTM (Root of Trust Measurement)
* Ability to configure ciphers used by the TPM 

## Requirements
* Requires a JDK 8 compatible development environment at compile time  
* A TPM 2.0 module and a Java 8 compatible JRE must be abilable at runtime. 

## Getting Stasrted 
Please refer to the example provided in the wiki [Securing Database Credentials](../../wiki/Overview-of-Operation#example-securing-database-credentials) to get started. 
