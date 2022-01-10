##############################################
# Copyright (c) 2021-2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##############################################

import os.path
import random
import sys
import time
from subprocess import Popen
from subprocess import PIPE


def print_help():
    content = "\n" \
              "Usage: signtool.jar -scope <simple|all|`component`> -n <round, default 1> <--random>\n" \
              "    signtool.jar : Main progress jar file\n" \
              "    component: \n" \
              "    --random: random test, default false" \
              "\n" \
              "Example: \n" \
              "    signtool.jar \n" \
              "    signtool.jar -scope all -n 1000\n" \
              "    signtool.jar -scope generate-profile-cert\n" \
              "    signtool.jar -n 50 --random\n" \
              "\n"

    print(content)
    pass


def random_pwd():
    min_pwd = 100000
    max_pwd = 999999
    return random.randint(min_pwd, max_pwd), random.randint(min_pwd, max_pwd)


keystorePwd, keyPwd = random_pwd()


random_scope = {
    'generate-keypair': {
        'required': {
            'keyAlias': 'oh-app1-key-v1',
            'keyAlg': ["RSA", "ECC"],
            'keySize': ["2048", "3072", "4096", "NIST-P-256", "NIST-P-384"],
            'keystoreFile': ['ohtest.jks', 'ohtest.p12']
        },
        'others': {
            'keyPwd': '123456',
            'keystorePwd': '123456'
        }
    },
    'generate-csr': {
        'required': {
            'keyAlias': 'oh-app1-key-v1',
            'signAlg': ["SHA256withRSA", "SHA384withRSA", "SHA256withECDSA", "SHA384withECDSA"],
            'subject': "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
            'keystoreFile': ['ohtest.jks', 'ohtest.p12'],
            'outFile': 'oh-app1-key-v1.csr'
        },
        'others': {
            'keyPwd': '123456',
            'keystorePwd': '132456'
        }
    },
    'generate-ca': {
        'required': {
            'keyAlias': ['oh-ca-key-v1', "oh-app-sign-srv-ca-key-v1"],
            'signAlg': ["SHA256withRSA", "SHA384withRSA", "SHA256withECDSA", "SHA384withECDSA"],
            'keyAlg': ['RSA', 'ECC'],
            'keySize': ["2048", "3072", "4096", "NIST-P-256", "NIST-P-384"],
            'subject': ["C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                        "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA"],
            'keystoreFile': ['ohtest.jks', 'ohtest.p12'],
            'outFile': 'app-sign-srv-ca.cer'
        },
        'others': {
            'keyPwd': '123456',
            'keystorePwd': '132456',
            'issuer': 'C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA',
            'issuerKeyAlias': 'oh-app-sign-srv-ca-key-v1',
            'issuerKeyPwd': '123456',
            'validity': '365',
            'basicConstraintsPathLen': '2'
        }
    },
    'generate-cert': {
        'required': {
            'keyAlias': ['oh-sub-key-v1', 'oh-ca-key-v1'],
            'signAlg': ["SHA256withRSA", "SHA384withRSA", "SHA256withECDSA", "SHA384withECDSA"],
            'subject': "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
            'issuer': 'C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA',
            'issuerKeyAlias': 'oh-ca-key-v1',
            'extKeyUsage': 'codeSignature',
            'keyUsage': ['digitalSignature,nonRepudiation,keyEncipherment',
                         'dataEncipherment,keyAgreement, certificateSignature, crlSignature',
                         'encipherOnly, encipherOnly'],
            'keystoreFile': ['ohtest.jks', 'ohtest.p12'],
            'outFile': 'app1.cer'
        },
        'others': {
            'extKeyUsage': ['serverAuthentication', 'clientAuthentication', 'emailProtection'],
            'extKeyUsageCritical': ['false', 'true'],
            'keyUsageCritical': ['false', 'true'],
            'issuerKeyPwd': '123456',
            'keyPwd': '123456',
            'validity': '365',
            'keystorePwd': '123456'
        }
    }
}

simple_scope = {
    'generate-keypair': [
        'generate-keypair -keyAlias "oh-app1-key-v1" -keyPwd 123456 -keyAlg ECC -keySize NIST-P-256 '
        '-keystoreFile "ohtest.jks" -keystorePwd 123456',

        'generate-keypair -keyAlias "oh-app1-key-v1" -keyPwd 123456 -keyAlg RSA -keySize 2048 '
        '-keystoreFile  "ohtest.p12" -keystorePwd 123456'
    ],
    'generate-csr': [
        'generate-csr -keyAlias "oh-app1-key-v1" -keyPwd 123456 -subject  '
        '"C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -signAlg SHA256withECDSA  '
        '-keystoreFile  "ohtest.jks" -keystorePwd 123456 -outFile "oh-app1-key-v1.csr"'
    ],
    'generate-ca': [
        'generate-ca -keyAlias "oh-root-ca-key-v1" -subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA" '
        '-validity 365 -signAlg SHA384withECDSA  -keystoreFile  "ohtest.jks" -keystorePwd 123456  '
        '-outFile "root-ca1.cer" -keyAlg ECC -keySize NIST-P-256',

        'generate-ca -keyAlias "oh-root-ca-key-v1" -subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA" '
        '-validity 365 -signAlg SHA384withECDSA  -keystoreFile  "ohtest.p12" -keystorePwd 123456  '
        '-outFile "root-ca2.cer" -keyAlg RSA -keySize 2048',

        'generate-ca -keyAlias "oh-app-sign-srv-ca-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Root CA" -issuerKeyAlias "oh-root-ca-key-v1" -subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN= Application Signature Service CA" -validity 365 -signAlg SHA384withECDSA  -keystoreFile  "ohtest.jks" '
        '-keystorePwd 123456  -outFile "app-sign-srv-ca1.cer" -keyAlg ECC -keySize NIST-P-256',

        'generate-ca -keyAlias "oh-app-sign-srv-ca-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Root CA" -issuerKeyAlias "oh-root-ca-key-v1" -subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN= Application Signature Service CA" -validity 365 -signAlg SHA384withECDSA  -keystoreFile  "ohtest.p12" '
        '-keystorePwd 123456  -outFile "app-sign-srv-ca2.cer" -keyAlg RSA -keySize 2048'
    ],
    'generate-cert': [
        'generate-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" '
        '-subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -validity 365 '
        '-keyUsage digitalSignature -extKeyUsage codeSignature -signAlg SHA256withECDSA  '
        '-keystoreFile  "ohtest.jks" -keystorePwd 123456 -outFile "single-app1.cer" -keyPwd 123456'
    ],
    'generate-app-cert': [
        'generate-app-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" -subject '
        '"C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -validity 365 -signAlg SHA256withECDSA  '
        '-keystoreFile  "ohtest.jks" -keystorePwd 123456 -outFile "app1.cer" -keyPwd 123456',

        'generate-app-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" -subject '
        '"C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -validity 365 -signAlg SHA256withECDSA  '
        '-keystoreFile  "ohtest.jks" -keystorePwd 123456 -outFile "app-release1.pem" '
        '-subCaCertFile app-sign-srv-ca1.cer -outForm certChain -rootCaCertFile root-ca1.cer -keyPwd 123456',

        'generate-app-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" -subject '
        '"C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -validity 365 -signAlg SHA256withECDSA  '
        '-keystoreFile  "ohtest.p12" -keystorePwd 123456 -outFile "app2.cer" -keyPwd 123456',

        'generate-app-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" -subject '
        '"C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -validity 365 -signAlg SHA256withECDSA  '
        '-keystoreFile  "ohtest.p12" -keystorePwd 123456 -outFile "app-release2.pem" '
        '-subCaCertFile app-sign-srv-ca2.cer -outForm certChain -rootCaCertFile root-ca2.cer -keyPwd 123456'
    ],
    'generate-profile-cert': [
        'generate-profile-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" '
        '-subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" '
        '-validity 365 -signAlg SHA256withECDSA  -keystoreFile  "ohtest.jks" '
        '-keystorePwd 123456 -outFile "profile1.cer" -keyPwd 123456',

        'generate-profile-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" '
        '-subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" -validity 365 '
        '-signAlg SHA256withECDSA -keystoreFile  "ohtest.jks" -keystorePwd 123456 -outFile "profile-release1.pem" '
        '-subCaCertFile app-sign-srv-ca1.cer -outForm certChain '
        '-rootCaCertFile root-ca1.cer -keyPwd 123456',

        'generate-profile-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" '
        '-subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" '
        '-validity 365 -signAlg SHA256withECDSA  -keystoreFile  "ohtest.p12" '
        '-keystorePwd 123456 -outFile "profile2.cer" -keyPwd 123456',

        'generate-profile-cert -keyAlias "oh-app1-key-v1" -issuer "C=CN,O=OpenHarmony,OU=OpenHarmony Community,'
        'CN=Application Signature Service CA" -issuerKeyAlias "oh-app-sign-srv-ca-key-v1" '
        '-subject  "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release" '
        '-validity 365 -signAlg SHA256withECDSA  -keystoreFile  "ohtest.p12" '
        '-keystorePwd 123456 -outFile "profile-release2.pem" -subCaCertFile app-sign-srv-ca2.cer -outForm certChain '
        '-rootCaCertFile root-ca2.cer -keyPwd 123456'
    ],
    'sign-profile': [
        'sign-profile -mode localSign -keyAlias "oh-app1-key-v1" -profileCertFile "profile-release1.pem" '
        '-inFile  "profile.json" -signAlg SHA256withECDSA  -keystoreFile  "ohtest.jks" -keystorePwd 123456 '
        '-outFile "app1-profile1.p7b"  -keyPwd 123456',
        'sign-profile -mode localSign -keyAlias "oh-app1-key-v1" -profileCertFile "profile-release2.pem" '
        '-inFile  "profile.json" -signAlg SHA256withRSA  -keystoreFile  "ohtest.p12" -keystorePwd 123456 '
        '-outFile "app1-profile2.p7b"  -keyPwd 123456'
    ],
    'verify-profile': [
        'verify-profile -inFile "app1-profile1.p7b"',
        'verify-profile -inFile "app1-profile2.p7b"'
    ]
}

test_result = {}


def run_target(case, cmd):
    if not test_result.get(case, None):
        test_result[case] = {'times': 0, 'total_cost': 0, 'success': 0, 'fail': 0}

    case_result = test_result.get(case)
    case_result['times'] = case_result['times'] + 1
    start = time.time()

    command = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=True)

    out = command.stdout.readlines()
    with open("log.txt", mode='a+') as f:
        if len(out) > 0:
            f.writelines(cmd + "\r\n")
        for line in out:
            f.writelines(str(line.strip()) + "\r\n")

    success = True
    error = command.stderr.readlines()
    with open("error.txt", mode='a+') as f:
        if len(error) > 0:
            f.writelines(cmd + "\r\n")

        for line in error:
            success = False
            f.writelines(str(line.strip()) + "\r\n")

    command.wait()
    end = time.time()
    case_result['total_cost'] = case_result['total_cost'] + (end - start)

    if success:
        case_result['success'] = case_result['success'] + 1
    else:
        case_result['fail'] = case_result['fail'] + 1
    return success


def run_simple_case(case, jar_file):
    test_case = simple_scope.get(case, None)
    if not test_case:
        print("Not found test case: {}".format(case))
        exit(0)

    for k in test_case:
        cmd = 'java -jar {} {}'.format(jar_file, k)
        print("== Run command: {}".format(cmd))
        result = run_target(case, cmd)
        print("== Done command: {}".format(result))


def random_str():
    strs = "abcdefghjiklmnopqstuvwxyzABCDEFGHIJKLMNOPQRS TUVWXYZ1234567890~!@#ls%^&*()_+,./<>?;':"
    result = ''
    for i in range(random.randint(1, 30)):
        result = result + random.choice(strs)
    return result


def run_random_case(case, jar_file):
    test_case = random_scope.get(case, None)
    if not test_case:
        print("Not found test case: {}".format(case))
        exit(0)

    cmd = 'java -jar {} {}'.format(jar_file, case)
    for k, v in test_case.get('required').items():
        r = random.choice(['none', 'choice', 'choice', 'random'])
        if r == 'choice':
            cmd = cmd + ' -{} "{}" '.format(k, random.choice(v) if isinstance(v, list) else v)
        elif r == 'random':
            cmd = cmd + ' -{} "{}" '.format(k, random_str())

    for k, v in test_case.get('others').items():
        r = random.choice(['none', 'choice', 'choice', 'random'])
        if r == 'choice':
            cmd = cmd + ' -{} "{}" '.format(k, random.choice(v) if isinstance(v, list) else v)
        elif r == 'random':
            cmd = cmd + ' -{} "{}" '.format(k, random_str())

    print("== Run command: {}".format(cmd))
    result = run_target(case, cmd)
    print("== Done command: {}".format(result))


def run_all_case(case, jar_file):
    test_case = random_scope.get(case, None)
    if not test_case:
        print("Not found test case: {}".format(case))
        exit(0)

    cmd = 'java -jar {} {}'.format(jar_file, case)
    for ak, av in test_case.get('required').items():
        cmd = cmd + ' -{} "{}" '.format(ak, random.choice(av) if isinstance(av, list) else av)

    print("== Run command: {}".format(cmd))
    result = run_target(case, cmd)
    print("== Done command: {}".format(result))


def remove_keystore():
    for key_file in ['ohtest.jks', 'ohtest.p12']:
        if os.path.exists(key_file):
            os.remove(key_file)


def process_cmd(args):
    run_round = 1
    run_scope = 'simple'
    is_random = False

    if len(args) <= 1 or ('.jar' not in args[1]) or '--help' == args[1] or '-h' == args[1]:
        print_help()
        exit(0)

    jar_file = args[1]
    if not os.path.exists(jar_file):
        print("Jar file '{}' not found".format(jar_file))
        exit(0)

    if len(args) >= 3:
        try:
            for i in range(2, len(args), 1):
                if args[i] == '-n':
                    run_round = int(args[i + 1])
                elif args[i] == '-scope':
                    run_scope = args[i + 1]
                elif args[i] == '--random':
                    is_random = True
        except IndexError:
            print_help()
            exit(0)

    print('===  Start testing  ===')
    print('Scope: {}. Round: {}. Random: {}'.format(run_scope, run_round, is_random))

    if os.path.exists('log.txt'):
        os.remove('log.txt')
    if os.path.exists('error.txt'):
        os.remove('error.txt')

    for i in range(run_round):
        if run_scope == 'all':
            for r_scope, _ in random_scope.items():
                run_all_case(r_scope, jar_file)
        elif is_random:
            for r_scope, _ in random_scope.items():
                run_random_case(r_scope, jar_file)
        elif run_scope == 'simple':
            remove_keystore()
            for s_scope, _ in simple_scope.items():
                run_simple_case(s_scope, jar_file)
        else:
            run_simple_case(run_scope, jar_file)


if __name__ == '__main__':
    process_cmd(sys.argv)
    print("All test done")
    print("========================")
    for rk, rv in test_result.items():
        print("Case {}, run times: {}, avg cost: {}s, total success: {}, total fail: {}".format(rk, rv['times'], round(
            rv['total_cost'] / rv['times'], 2), rv['success'], rv['fail']))
    print("========================")
    print("See log.txt / error.txt")
