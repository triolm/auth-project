import os
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

load_dotenv()

# message = Mail(
#     from_email='triolm24+authapp@polyprep.org',
#     to_emails='triolm24@polyprep.org',
#     subject='I am sending an email',
#     html_content='This is the body of my email. <strong>This text should be bold.</strong>')
# try:
#     sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
#     response = sg.send(message)
#     print(response.status_code)
#     print(response.body)
#     print(response.headers)
# except Exception as e:
#     print(e.message)
