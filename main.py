import json
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To

import pymongo
import random
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)
import datetime

os.environ['TZ'] = 'US/Eastern'
twilioApiKey = os.environ['TWILIO_API_KEY']
mongoPwd = os.environ['MONGO_PWD']
# mongo setup
CONNECTION_STRING = f"mongodb+srv://awsLambda:{mongoPwd}@starvvenssimplefileshar.ruwbw.mongodb.net/myFirstDatabase" \
                    f"?retryWrites=true&w=majority"
s3_client = boto3.client('s3')
myclient = pymongo.MongoClient(CONNECTION_STRING)
mydb = myclient["starvens"]
mycol = mydb["uniqueUrls"]
otpCollection = mydb["otpsGenerated"]
sendOtpTemplateId = 'd-c8703cd4d4c64ec0abe7f72152871c50'
sendFileLinkTemplateId = 'd-5ee3dbd5c67440a6805ff2ad68ca0e92'

sample_resp = {
    'statusCode': 200,
    "headers": {
        'Access-Control-Allow-Origin': '*'
    },
}


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


def sendEmailUsingTemplate(req, templateId, templateData):
    logger.info(req)
    msg = Mail(
        from_email='no-reply@starvens.com',
        to_emails=req['toEmail']
        # to_emails=req['toEmail'],
        # subject=req['subject'],
        # html_content=f'<h1>Subject:</h1><br/><p>{req["content"]}</p>'
    )
    msg.template_id = templateId
    msg.dynamic_template_data = templateData

    try:
        sg = SendGridAPIClient(twilioApiKey)
        resp = sg.send(msg)
        logger.info(resp.body)
        return {'status': 'success'}
    except Exception as e:
        logger.error(e)


def generateOTP(req):
    logger.info(req)
    otp = ''
    for i in range(6):
        otp += str(random.randint(0, 9))
    rowNeeded = {**req, 'createdAt': datetime.datetime.now(), 'otp': otp, 'failedAttempts': 0,
                 'successAttempt': 0, 'updatedAt': datetime.datetime.now()}
    try:
        # send otp to the email later update the mongo weather otp
        # has already sent or not
        # toEmails = To(email=req["toEmail"], dynamic_template_data={'otp': otp})
        toEmails = [(req["toEmail"], 'Starvens User')]
        emailData = {'toEmail': toEmails,
                     'otp': otp,
                     'subject': f'One Time Pin (OTP) for Your Recent Starvens FileShare Request {otp}',
                     'content': f'For security purposes surrounding your Starvens request, please provide the '
                                f'following One-Time-Password (OTP): {otp}'}
        # emailRes = sendEmail(emailData)
        templateData = {'otp': otp}
        emailRes = sendEmailUsingTemplate(emailData, sendOtpTemplateId, templateData)
        if emailRes['status'] == 'success':
            rowNeeded = {**rowNeeded, 'isOTPSent': True}
            otpCollection.insert_one(rowNeeded)
            logger.info(rowNeeded)
            return {'status': 'success'}
        else:
            return {'status': 'Something went wrong'}
    except Exception as e:
        logger.error(e)
        raise e


def validateOTP(req):
    logger.info(req)
    findQuery = {'curId': req['curId']}
    existingRecord = otpCollection.find_one(findQuery)
    prevFailed = existingRecord['failedAttempts']
    timeDiff = datetime.datetime.now() - existingRecord['createdAt']
    logger.info(timeDiff.total_seconds())
    if prevFailed >= 3 or timeDiff.total_seconds() > 3600:
        raise Exception(f'OTP verification failed for below request:: {req}')
    usersOtp = req['usersOtp']
    # logger.info(usersOtp, str(existingRecord['otp']))
    if str(usersOtp) == existingRecord['otp']:
        newvalues = {"$set": {'updatedAt': datetime.datetime.now(), 'successAttempt': 1}}
        resp = sendFileLinkToUser(req)
        if resp['status'] != 'success':
            raise Exception(f'not able to send link to user:: {req}')
        otpCollection.update_one(findQuery, newvalues)
        return {'status': 'success'}
    else:
        newvalues = {"$set": {'updatedAt': datetime.datetime.now(), 'failedAttempts': prevFailed + 1}}
        otpCollection.update_one(findQuery, newvalues)
        logger.info(f'failed attempt for request :: {req}')
        raise Exception(f'OTP verification failed for below request :: {req} ')


# when otp verification is success send
# the link to users required email
def sendFileLinkToUser(req):
    toEmails = [(req["toEmail"], 'Starvens User')]
    emailData = {'toEmail': toEmails}
    # emailRes = sendEmail(emailData)
    templateData = {'fileSize': '', 'expDate': str(datetime.datetime.now() + datetime.timedelta(days=1)),
                    'fileLink': req['fileLocation']}
    return sendEmailUsingTemplate(emailData, sendFileLinkTemplateId, templateData)


def sendEmail(req):
    logger.info(req)
    msg = Mail(
        from_email='no-reply@starvens.com',
        to_emails=req['toEmail'],
        subject=req['subject'],
        html_content=f'<h1>Subject:</h1><br/><p>{req["content"]}</p>'
    )

    try:
        sg = SendGridAPIClient(twilioApiKey)
        resp = sg.send(msg)
        logger.info(resp.body)
        return {'status': 'success'}
    except Exception as e:
        logger.error(e)


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

        # this is for sending the actual email after otp validation
        if event['resource'] == '/sendemail':
            temp = sendEmail(tempBody)
            return {**sample_resp, 'body': json.dumps(temp)}

        if event['resource'] == '/generateotp':
            temp = generateOTP(tempBody)
            return {**sample_resp, 'body': json.dumps(temp)}

        if event['resource'] == '/validateotp':
            temp = validateOTP(tempBody)
            return {**sample_resp, 'body': json.dumps(temp)}

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
        response = s3_client.generate_presigned_url('put_object', Params={'Bucket': 'starvensdriveguest',
                                                                          'Key': f'{curUrl}/{fileName}',
                                                                          'ContentType': 'binary/octet-stream'})

        mycol.insert_one(rowInDb)
        logger.info('successfully inserted into mongo')

        temp = {'presignedUrl': response,
                'publicUrl': f'https://starvensdriveguest.s3.amazonaws.com/{curUrl}/{fileName}'}

        # x = mycol.insert_one(mydict)
        return {**sample_resp, 'body': json.dumps(temp)}
    except Exception as e:
        logger.exception(e)
        raise e
