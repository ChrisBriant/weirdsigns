# using SendGrid's Python Library
# https://github.com/sendgrid/sendgrid-python
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from weirdsigns import db

FROM_ADDRESS = "admin@weirdsigns.co.uk"
ROOT_URL = "http://127.0.0.1:5000/"
SITE_NAME = "Weird Signs"

def sendconfirmation(to, hash, username):
    msgbody = '<p>You have registed to use ' + SITE_NAME + ' with the user name ' + username + '.' \
             'Please click on the link below to confirm.' + '<p><a href="' + ROOT_URL + \
             'confirm/' + str(hash) + '">Confirm Registration</a>.</p>' + \
             '<p>The account will expire within one hour</p>'
    message = Mail(
        from_email=FROM_ADDRESS,
        to_emails=to,
        subject='Welcome to ' + SITE_NAME + ' - Please Confirm your Email Address',
        html_content= msgbody)
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        print(sg)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)


def sendforgot(to, hash):
    msgbody = '<p>Please click on the link below to reset your password</p>' \
             '<p><a href="' + ROOT_URL + 'forgot/' + str(hash) + '">Reset Password</a>.</p>'
    message = Mail(
        from_email=FROM_ADDRESS,
        to_emails=to,
        subject='' + SITE_NAME + ' - Reset your password',
        html_content= msgbody)
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)

def send_to_admin(username, message):
    msgbody = '<p>' + username + ' sent the message below:</p>' + \
              '<p style="text-decoration:italic;">' + message + '</p>'
    message = Mail(
        from_email=FROM_ADDRESS,
        to_emails="cbri4nt@gmail.com",
        subject='' + username + ' - sent a message',
        html_content= msgbody)
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)
