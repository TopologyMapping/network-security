import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import time

from settings import SENDER, SMTP_PASS, SMTP_PORT, SMTP_SERVER, SMTP_USER, USERS_FILE, REPORT_FILES

def load_html_template(email):
    path = os.path.join(REPORT_FILES, f"{email}.html")
    with open(path, "r", encoding="utf-8") as file:
        return file.read()

def attach_inline_image(msg, image_path, content_id, filename):
    if os.path.exists(image_path):
        with open(image_path, "rb") as img_file:
            img = MIMEImage(img_file.read())
            img.add_header("Content-ID", f"<{content_id}>")
            img.add_header("Content-Disposition", "inline", filename=filename)
            msg.attach(img)
    else:
        print(f"Error finding the image: {image_path}")

def send_email(server, name, email, has_vote):
    email_body = load_html_template(email) # files are named with the "email.html" format
    
    msg = MIMEMultipart("related")
    msg["From"] = SENDER
    msg["To"] = email
    msg["CC"] = "" # adjust
    msg["Subject"] = "" # change to a subject msg, like -> msg["Subject"] = "Bem-vindo(a) ao DefectDojo Crivo!"

    alternative = MIMEMultipart("alternative") # safeguard
    alternative.attach(MIMEText(email_body, "html"))
    msg.attach(alternative)

    if has_vote == "0": # flags to identify different e-mail templates (that contains or not images)
        images = [
            (os.path.join(REPORT_FILES, f"{email}.png"), "relatorio_pessoal", "relatorio.png"),
            (os.path.join(REPORT_FILES, f"feat_importance_user_{email}_2x1.png"), "importancia", "importancia.png"),
        ]

        for path, cid, filename in images:
            attach_inline_image(msg, path, cid, filename)
    
    email = [email, ""] # insert o remove strings here to send copies of the email to others users

    try:
        server.sendmail(SENDER, email, msg.as_string())
        print(f"Email sent to {name} <{email}>")
    except Exception as e:
        print(f"Error sending email to {name} <{email}>: {e}")

def send_emails():
    with open(USERS_FILE, "r", encoding="utf-8") as file:
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)

                for line in file:
                    name, email, has_vote = map(str.strip, line.split(","))
                    send_email(server, name, email, has_vote)
                    time.sleep(25)
        except Exception as e:
            print(f"Error: {e}")
        
send_emails()