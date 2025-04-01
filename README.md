# hsm-service

hsm-service can be used to store AESSecretKey and RSAKeyPair in
1. HSM device
2. Google Cloud HSM

The service is at POC level and tested with HSM simulator and actual Google Cloud HSM.

Connectivity with HSM simulator
--------------------------------
Service is tested with SoftHSM simulator which can be downloaded from https://github.com/disig/SoftHSM2-for-Windows

Configure pkcs11.module-path parameter with the simulator .dll file in application.yml

Test the service with REST endpoints from Postman.

 Connectivity with Google Cloud HSM
-----------------------------------
Refer to section 'Before you Begin' from https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-java-service for setting up environment to connect to Google Cloud for HSM service. Alternately https://cloud.google.com/run/docs/setup can be referred to setup an environment.
 - Creates a configuration locally with credentials stored  at C:\Users\<user-account>\AppData\Roaming\gcloud\application_default_credentials.json 