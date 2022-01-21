# developtools_hapsigner

* Description
* catalogue
* Installation
* Instructions
* Auto generate script

#### Description
In order to ensure the integrity and reliability of the OpenHarmony application, the application needs to be signed when the application is built, so that the application can be installed, run, and debugged on a real device. This warehouse provides a jar toolkit with functions such as certificate generation and hap package signature.

#### catalogue

    developtools_hapsigner

    ├── autosign        # One-click signature script
    ├── docs            # Documentation
    ├── hapsigntool     # Main code
          ├──hap_sign_tool # The main program entrance completes the basic verification of input parameters
          ├──hap_sign_tool_lib  # Signature tool library, parses the command word and parameter list, and realizes the logical function of each module
    ├── tools   # Automated test script

#### Installation
1. Clone this git
2. Configure the operating environment ：Gradle 7.1, JDK 8
3. Command to locate developtools_hapsigner/hapsigntool/
4. Compile project with **gradle build** or **gradle jar**
5. You can find jar at ./hap_sign_tool/build/libs/hap_sign_tool-xxxx.jar


#### Instructions
Command example：

```shell
java -jar <signature tool.jar> <command> <params>
```

Complete usage example：
```shell
java -jar hap_sign_tool.jar generate-csr -keyAlias "oh-app1-key-v1" -keyPwd ***** -subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -signAlg SHA256withECDSA  -keystoreFile  "D:\OH\ohtest.jks" -keystorePwd ***** -outFile "D:\OH\oh-app1-key-v1.csr"
```
You can also use -help to view the complete instructions
```shell
java -jar hap_sign_tool.jar -help
```
****
#### Auto generate script
You can also find a script in **autosign** folder
* start_create.sh/start_create.bat
* start_sign.sh/start_sign.bat
* auto_sign_main.py
* auto_sign.conf

Steps：
1. Environment python3.x is required
2. Also related hap_sign_tool.jar 
3. Get your unsigned hap package and Provision profile templates
4. Edit auto_sign.conf and replace it with your information
5. Run start_create.sh and start_sign.sh in Linux os
6. Or run start_create.bat and start_sign.bat in Window os

****

#### Command description：

* generate-keypair : generate key pair
* generate-csr : generate certificate signing request
* generate-cert : generate certificate in full, large and complete, any certificate can be generated
* generate-ca : generate root/subject CA certificate, if the key does not exist, generate the key together
* generate-app-cert : generate application debug/release certificate
* generate-profile-cert : generate application debug/release certificate
* sign-profile : Provision Profile file signature
* verify-profile : Provision Profile file verification
* sign-app : application package signature
* verify-app : application package file verification

