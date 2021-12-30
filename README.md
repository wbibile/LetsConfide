# LetsConfide 
LetsConfide is a library for securing and managing secret information such as database credentials used by software. 
The current implementation is in Java however, the underlying algorithms and data structures selected are language independent.  

## Features
* Input and manage secret information using YAML 
* Encryption keys are backed by a TPM 2.0 module
* TPM storage keys are authenticated using RTM (Root of Trust Measurement)
* Ability to configure ciphers used by the TPM 

