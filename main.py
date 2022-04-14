import json
import os


import pymongo
import random
import boto3
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
import datetime

os.environ['TZ'] = 'US/Eastern'
# mongo setup
CONNECTION_STRING = "mongodb+srv://awsLambda:<password>@starvvenssimplefileshar.ruwbw.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
s3_client = boto3.client('s3')
myclient = pymongo.MongoClient(CONNECTION_STRING)
mydb = myclient["starvens"]
mycol = mydb["uniqueUrls"]


def generateUniqueURL():
    required = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:@!$*='
    maxLength = 35
    totLen = len(required)
    ans = []
    for i in range(maxLength):
        x = random.randint(0, totLen - 1)
        ans.append(required[x])
    return ''.join(ans)


def checkIfUrlExistInMongo(url):
    logger.info('came to method')
    records = mycol.find_one({"uniqueUrl": url})
    records = records if records else []
    for _ in records:
        logger.info('already in db')
        return True
    return False


def lambda_handler(event, context):
    try:
        # get the file name
        logger.info(str(event))
        # event = json.loads(event)
        # tempBody = event['body']
        # fileName = tempBody['fileName']
        # ip = tempBody['ipAddress']
        tempBody = event['body']
        tempBody = json.loads(tempBody)
        fileName = tempBody['fileName']
        ip = tempBody['ipAddress']
        logger.info(f'{fileName}{ip}')

        while True:
            curUrl = generateUniqueURL()
            logger.info(curUrl)
            if not checkIfUrlExistInMongo(curUrl):
                logger.info('breaked')
                break
            logger.info('should not be here')
        logger.info(f'generated url :: {curUrl}')

        # TODO
        rowInDb = {
            "uniqueUrl": f'https://starvensdriveguest.s3.amazonaws.com/{curUrl}/{fileName}',
            "fileName": fileName,
            "isFileUploadedToS3": False,
            "ipAddress": ip,
            "cratedAt": str(datetime.datetime.now())
        }
        logger.info(f'data need to be inserted : {str(rowInDb)}')

        # generate presigned url
        # TODO expiration time
        # response = s3_client.generate_presigned_url('put_object', Params={'Bucket': 'starvensdriveguest', 'Key': f'{curUrl}/{fileName}'})
        response = s3_client.generate_presigned_url('put_object', Params={'Bucket': 'starvensdriveguest', 'Key': f'{curUrl}/{fileName}', 'ContentType': 'binary/octet-stream'})

        mycol.insert_one(rowInDb)
        logger.info('successfully inserted into mongo')

        temp = {'presignedUrl': response, 'publicUrl': f'https://starvensdriveguest.s3.amazonaws.com/{curUrl}/{fileName}'}

        # x = mycol.insert_one(mydict)
        return {
            'statusCode': 200,
            "headers": {
                'Access-Control-Allow-Origin': '*'
            },
            # 'body': json.dumps(event)
            'body': json.dumps(temp)
        }
    except Exception as e:
        logger.exception(e)
        raise e

