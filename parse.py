import json
import boto3
import os

def parseResults(t, c, notify):
    result = json.loads(t)

    if int(result['status']) != int(c['expected_http']):
        if notify == True:
            msg = f"Expected {c['expected_http']} but got {result['status']} for {result['url']}"
            notifySns(t,msg)

    # print(result['status'])
    # print(c['expected_http'])
    # print(notify)

def notifySns(t,msg):
    result = json.loads(t)

    arn = os.environ['snsArn']
    client = boto3.client('sns')
    response = client.publish(
        TargetArn=arn,
        Message=json.dumps({'default': msg}),
        Subject="UNEXPECTED: " + result['hostname'],
        MessageStructure='json'
    )