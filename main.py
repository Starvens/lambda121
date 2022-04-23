import json
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, To
import pytz
import uuid

import pymongo
import random
import boto3
import logging
import bcrypt

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
urlCollection = mydb["uniqueUrls"]
otpCollection = mydb["otpsGenerated"]
sendOtpTemplateId = 'd-c8703cd4d4c64ec0abe7f72152871c50'
sendFileLinkTemplateId = 'd-5ee3dbd5c67440a6805ff2ad68ca0e92'
timeZone = pytz.timezone('US/Central')

sample_resp = {
    'statusCode': 200,
    "headers": {
        'Access-Control-Allow-Origin': '*'
    },
}


def generateUniqueURL():
    required = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$*'
    maxLength = 35
    totLen = len(required)
    ans = []
    for i in range(maxLength):
        x = random.randint(0, totLen - 1)
        ans.append(required[x])
    return ''.join(ans)


def generateUrlByCheckingMongo():
    while True:
        curUrl = generateUniqueURL()
        logger.info(curUrl)
        if not checkIfUrlExistInMongo(curUrl):
            logger.info('breaked')
            break
        logger.info('should not be here')
    return curUrl


def getRowFromMongoForUniqueUrl(uniqueUrl):
    records = urlCollection.find_one({'uniqueUrl': uniqueUrl})
    records = [records] if records else []
    return records


def checkIfUrlExistInMongo(url):
    logger.info('came to method')
    records1 = urlCollection.find_one({"uniqueId": url})
    records2 = urlCollection.find_one({"privateId": url})
    if records1 or records2:
        logger.info('already in db')
        return True
    return False


def savePwd(req):
    mongoRow = urlCollection.find_one({'consId': req['uri']})
    if not mongoRow:
        raise Exception(f'The given uri doesnot exist in mongo {req}')
    hashedpwd = bcrypt.hashpw(req['pwd'].encode('utf-8'), bcrypt.gensalt())
    logger.info(f'the hashed password is {hashedpwd}')
    newvalues = {"$set": {'updatedAt': datetime.datetime.now(), 'pwd': hashedpwd}}
    findQuery = {'uniqueId': mongoRow['uniqueId']}
    urlCollection.update_one(findQuery, newvalues)
    return {'status': 'success'}


def validatePwd(req):
    findQuery = {'privateId': req['uri']}
    fileInMongo = urlCollection.find_one(findQuery)
    logger.info(f'file in mongo:: {fileInMongo}')
    if not fileInMongo:
        raise Exception(f'The given url not found in mongo:: {req["uri"]}')
    if bcrypt.checkpw(req['pwd'].encode('utf-8'), fileInMongo['pwd']):
        logger.info(f'password match')
        response = s3_client.generate_presigned_url('get_object', Params={'Bucket': 'starvensdrive',
                                                                          'Key': f'{fileInMongo["uniqueId"]}/{fileInMongo["fileName"]}',
                                                                          })
        return {'fileName': fileInMongo['fileName'], 'fileSize': fileInMongo['fileSize'],
                'fileUnits': fileInMongo['fileUnits'], 'presignedUrl': response}
    else:
        raise Exception(f'Password doesnot match with the required password')


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
    mongoRow = getRowFromMongoForUniqueUrl(req['fileLocation'])
    if len(mongoRow) == 0:
        raise Exception(f'noentry there in mongo for given unique url: {req}')
    mongoRow = mongoRow[0]
    expTime = datetime.datetime.now(timeZone) + datetime.timedelta(days=1)
    # emailRes = sendEmail(emailData)
    templateData = {'fileSize': f'{mongoRow["fileSize"]} {mongoRow["fileUnits"]}',
                    'expDate': str(f'{expTime.strftime("%d %B, %Y, %I:%M %p")} US/Central'),
                    'fileLink': req['fileLocation'], 'fileName': mongoRow['fileName'], 'subject': req['subject'],
                    'content': req['content']}
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


def getAllUrls(qParams):
    consId = qParams['consid']
    mongoResp = urlCollection.find_one({'consId': consId})
    if not mongoResp:
        raise Exception(f'not able to find the consolodiate id given: {consId}')
    return {'pubUrl': f'http://localhost:3000/share/0/{mongoResp["uniqueId"]}',
            'priUrl': f'http://localhost:3000/share/1/{mongoResp["privateId"]}'}


def getFileDetails(qParams):
    if 'public' in qParams:
        publicId = qParams['public']
        fileInMongo = urlCollection.find_one({'uniqueId': publicId})
        logger.info(f'the mongo record found is :: {fileInMongo} ')
        if not fileInMongo:
            raise Exception(f'not able to find given file by public URI: {publicId}')
        response = s3_client.generate_presigned_url('get_object', Params={'Bucket': 'starvensdrive',
                                                                          'Key': f'{publicId}/{fileInMongo["fileName"]}',
                                                                          })
        return {'fileName': fileInMongo['fileName'], 'fileSize': fileInMongo['fileSize'],
                'fileUnits': fileInMongo['fileUnits'], 'presignedUrl': response}
    else:
        raise Exception(f'Not able to find the file for given parameters it should be either private or public')


def getPresignedUrlForUpload(tempBody):
    fileName = tempBody['fileName']
    ip = tempBody['ipAddress']
    logger.info(f'FileName: {fileName}  IP: {ip}')

    consId = str(uuid.uuid4())
    curUrl = generateUrlByCheckingMongo()
    privateId = generateUrlByCheckingMongo()
    logger.info(f'generated url :: consolidatedId:: {consId} publicUrl :: {curUrl} privateUrl: {privateId}')

    # TODO
    rowInDb = {
        "consId": consId,
        "uniqueUrl": f'https://starvensdrive.s3.amazonaws.com/{curUrl}/{fileName}',
        "uniqueId": curUrl,
        "privateId": privateId,
        "fileName": fileName,
        "fileSize": tempBody['fileSize'],
        "fileUnits": tempBody['units'],
        "flatSize": tempBody['flatSize'],
        "isFileUploadedToS3": False,
        "ipAddress": ip,
        "cratedAt": str(datetime.datetime.now()),
        "createdCST": str(datetime.datetime.now())
    }
    logger.info(f'data need to be inserted : {str(rowInDb)}')

    # generate presigned url
    # TODO expiration time
    # response = s3_client.generate_presigned_url('put_object',
    # Params={'Bucket': 'starvensdriveguest', 'Key': f'{curUrl}/{fileName}'})
    response = s3_client.generate_presigned_url('put_object', Params={'Bucket': 'starvensdrive',
                                                                      'Key': f'{curUrl}/{fileName}',
                                                                      'ContentType': 'binary/octet-stream'})

    urlCollection.insert_one(rowInDb)
    logger.info('successfully inserted into mongo')

    # temp = {'presignedUrl': response, 'publicUrl': f'http://localhost:3000/share/{curUrl}/{fileName}'}
    temp = {'presignedUrl': response, 'publicUrl': consId}
    return temp


def lambda_handler(event, context):
    try:
        # get the file name
        logger.info(str(event))
        tempBody = event['body']
        tempBody = tempBody if tempBody else "{}"
        queryParams = event['queryStringParameters']
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

        if event['resource'] == '/validatepwd':
            temp = validatePwd(tempBody)
            return {**sample_resp, 'body': json.dumps(temp)}

        if event['resource'] == '/setpwd':
            temp = savePwd(tempBody)
            return {**sample_resp, 'body': json.dumps(temp)}

        if event['resource'] == '/getallurls':
            temp = getAllUrls(queryParams)
            return {**sample_resp, 'body': json.dumps(temp)}

        if event['resource'] == '/createsignedurl':
            temp = getPresignedUrlForUpload(tempBody)
            return {**sample_resp, 'body': json.dumps(temp)}

        if event['resource'] == '/file':
            temp = getFileDetails(queryParams)
            return {**sample_resp, 'body': json.dumps(temp)}

    except Exception as e:
        logger.exception(e)
        raise e
