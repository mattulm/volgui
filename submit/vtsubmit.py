
<!-- saved from url=(0069)https://jon.oberheide.org/blog/wp-content/uploads/2008/11/vtsubmit.py -->
<html><head><meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">#!/usr/bin/env python

# vtsubmit.py
# VirusTotal Submission Script
# Jon Oberheide &lt;jon@oberheide.org&gt;
# http://jon.oberheide.org

import os, sys, email, smtplib, hashlib

SMTP_HOST = '_HOST_'
SMTP_PORT = 587
SMTP_USER = '_USER_'
SMTP_PASS = '_PASS_'

TO_ADDR   = 'scan@virustotal.com'
FROM_ADDR = '_EMAIL_'

def main():
    if len(sys.argv) == 1:
        print 'please specify files to submit'
        sys.exit(1)

    filelist = sys.argv[1:]
    total = len(filelist)
    progress = 0

    for filename in filelist:
        progress += 1
        data = open(filename, 'rb').read()
        sha1 = hashlib.sha1(data).hexdigest()
        base = os.path.basename(filename)

        print '%d of %d: %s (%s)' % (progress, total, base, sha1)

        msg = email.MIMEMultipart.MIMEMultipart()
        msg['From'] = FROM_ADDR
        msg['To'] = TO_ADDR
        msg['Date'] = email.Utils.formatdate()
        msg['Subject'] = 'SCAN'

        part = email.MIMEBase.MIMEBase('application', 'octet-stream')
        part.set_payload(data)
        email.Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % base)
        msg.attach(part)

        smtp = smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT)
        if SMTP_USER and SMTP_PASS:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
        smtp.sendmail(FROM_ADDR, TO_ADDR, msg.as_string())
        smtp.close()

if __name__ == '__main__':
    main()
</pre></body></html>