from sys import exit
from argparse import ArgumentParser, Namespace
from datetime import datetime

from scanner import TargetParser, Enumerator, start_tls
from TLS.protocols import versions as p_versions

import os
import boto3
import json

from https_check import *
from parse import *

# ToDo
# cipher preference
# encrypted sni (https://tools.ietf.org/html/draft-ietf-tls-esni-02)


def print_start():
    print("Starting enumeration at: {}".format(datetime.now().strftime('%d-%m-%Y %H:%M:%S')))


def test(target, preamble, sni_name):

    enum = Enumerator(target)
    if sni_name:
        enum.sni_name = sni_name
    enum.set_clear_text_layer(preamble)
    enum.verbose = True  # Enumerator will print in verbose mode

    print_start()
    supported_protocols = enum.get_version_support(reversed(p_versions))

    if len(supported_protocols) == 0:
        for key, value in start_tls.items():
            if int(target.port) in value:  # Try again: adding a clear-text protocol for the port
                print_start()
                enum.set_clear_text_layer(key)
                supported_protocols = enum.get_version_support(reversed(p_versions))
                break

    if len(supported_protocols) == 0:  # Try again with SNI extension disabled (all following actions will not use SNI)
        enum.sni = False
        print_start()
        supported_protocols = enum.get_version_support(reversed(p_versions))

    enum.downgrade_protection(supported_protocols)

    for p in supported_protocols:
        enum.get_cipher_support(p)
  
    if isinstance(supported_protocols,list) and len(supported_protocols) > 0:
        if p_versions[supported_protocols[0]] == p_versions['TLSv1_3'] and len(supported_protocols) > 1:
            enum.get_certificate(supported_protocols[1])
        else:
            enum.get_certificate(supported_protocols[0])


def lambda_handler(event, lambda_context):

    # parser = ArgumentParser(description='Scanner to enumerate encryption protocol support', prog='tlscan3')
    # parser.add_argument('target', type=str, help="specify target as: host:port e.g. www.example.com:443 or "
    #                                              "[::1]:443 for IPv6")
    # parser.add_argument('--version', action='version', version='%(prog)s 3.1')
    # p_group = parser.add_mutually_exclusive_group()
    # for key, value in start_tls.items():
    #     p_group.add_argument("--{}".format(key), dest=key, action='store_true',
    #                          help='Use {} as protocol layer'.format(key.upper()))
    # parser.add_argument('--sni', type=str, dest='sni', help="SNI name to use in the handshake")

    # args = parser.parse_args()

    # for key, value in start_tls.items():
    #     try:
    #         if getattr(args, key):
    #             preamble = key
    #             break
    #     except AttributeError:
    #         pass

    preamble = None

    try:
        dynamo_db = os.environ['DYNAMO_TABLE']
        # print(f"Dynamo table: {dynamo_db}")
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(dynamo_db)
        response = table.scan()
        print("====================================")
        for item in response['Items']:
            targetRecord = item
            
            targetConfig = json.loads(item['config'])

            # Check if the item is enabled to scan
            if targetRecord['enabled'] == True:
                # print(f"Target record: {targetRecord}")
                # print(f"Target config: {targetConfig}")
                # print(f"Target port: {targetConfig['port']}")

                if targetConfig['port'] == "":
                    targetConfig['port'] = "443"
                if targetConfig['sni'] == "":
                    targetConfig['sni'] = None
                if targetConfig['protocol'] == "":
                    targetConfig['protocol'] = "https"
                if targetConfig['path'] == "":
                    targetConfig['path'] = ""
                targetRecord['hostnamePort'] = targetRecord['hostname'] + ":" + targetConfig['port']
                
                if targetRecord['check_cert'] == True:
                    # Do the TLS scanning tasks here
                    try:
                        try:
                            t = TargetParser(targetRecord['hostnamePort']).get_target()
                            print(f"{ t }")
                        except ValueError:
                            print("[!] Failed to parse target, trying again by adding a default port (443)")
                            t = TargetParser(targetRecord['hostnamePort'] + ":443").get_target()
                        test(t, preamble, targetConfig['sni'])
                        # write results and last test timestamp here
                    except KeyboardInterrupt:
                        print(f"[!] Received termination signal, exiting!")
                        exit(3)
                    except:
                        print(f"[!] FATAL ERROR CERT CHECK HOST TARGET { targetRecord['hostnamePort'] }")

                if targetRecord['check_http'] == True:
                    # Port check here
                    try:
                        print(f"Attempting HTTP status check on { targetConfig['protocol']}://{targetRecord['hostname'] }:{ targetConfig['port'] }/{targetConfig['path']}")
                        t = doRequest(targetConfig['protocol'], targetRecord['hostname'], str(targetConfig['port']), targetConfig['path'])
                        print(f"{ t }")
                        parseResults(t, targetConfig, targetRecord['notify'])
                    except ValueError:
                        print(f"[!] FAILED TO PORT CHECK TARGET")
            else:
                print(f"[*] HOST TARGET { targetRecord['hostname'] } IS DISABLED")
            
            print("====================================")
    except:
        print(f"[!] FATAL ERROR CONNECTING TO DYNAMODB OR PARSING HOST TARGET { targetRecord['hostname'] }")

if __name__ == '__main__':
    os.environ['DYNAMO_TABLE'] = "tlscan"
    lambda_handler(False, False)
