#!/usr/bin/python
#
#	This script, takes a CLEAN text list of hosts/domains/urls, without quotes, commas or http/https
#    Example:
#       1:domain.com
#       2:domain2.com
#       3:domain3.com/foo/bar/index.txt
#       4:185.93.1.196
#
#       PRE-CLEAN your file, I'm not doing any error checking or string cleaning, that's a very deep rabbit hole.
#
#       A Sample 100URLs file is included
#       A Sample output file is included as well
#
#     This Script calls Zscaler's URL lookup API in batches (100 at a time) and generates a usable CSV file
#      documenting the url with up-to 4 Categories and up-to 4 Security categories
#
#      While the CSV is being written out, we check if the url resolves and include those results in the 2nd column:
#       DoesNotResolve
#       or
#       YES:172.67.153.22
#
#    Example:
#    url,dns_resolves,category_01,category_02,category_03,category_04,numCategories,secAlert_01,secAlert_02,secAlert_03,secAlert_04,numSecAlerts
#    domain.com,Blogs,Professional Services,(usually NULL),usually NULL),2,malware,cryptomining,(usually NULL),(usually NULL),2
#
#   You should already be familiar with Zscaler's API, how to log in, how to obfuscate the key, and execute calls.
#   If not, start with help.zscaler.com and type in API in the search bar.
#
#   This script also writes to both the console window and the file, if you don't like that unwind the
#     LogToConsoleAndFile function
#
#   This script is CopyLeft, NO WARRANTIES EXPRESSED OR IMPLIED, while this works on my computer it might not work on yours.
#

__author__ = 'mdisher@zscaler.com (Matt Disher / SE)'

import datetime
import json
import sys
import time
from itertools import islice
import requests
import socket

### Local Variables ###
outputFilename = 'output/100URLs_Development.csv'  # This the logFile/csv name in relation to the script, i'm not making the output directory make sure it exists.
urlsToCategorize = 'input/100URLs.txt'  # This is the file we're processing, one url per line, no quotes or commas adjust path as necessary
categoryDisplayName = "Sample 100-sh URLS to testfile."  # This is just a description that will be logged to the file.

# More Variables for Time/Header type
now = int(time.time())
start = now - (86400 * 30)
headers = {'content-type': 'application/json'}
orig_stdout = sys.stdout
start_time = time.time()

# Local Auth Variables
# I am not advocating you save your credentials here in the clear, but that's how this works.
#


username = 'admin@company.net'  # Admin username with API privileges
password = 'APIAdminP455word'    # password for the above account
apikey = 'sRPhfbi3kBrB1'      # instance API key < Unique to your environment
seed = 'sRPhfbi3kBrB1'        # also the API Key? < Unique to your environment
cloudName = "zscalertwo"     # this is the customer's cloud zscaler, zscloud, zscalertwo, zscalerthree, zscalerbeta


### Our Functions ###

# obsfucate API key function
def obfuscateApiKey():
    # seed = str(api)
    global now
    now = str(int(time.time() * 1000))
    n = now[-6:]
    r = str(int(n) >> 1).zfill(6)
    global key
    key = ""
    for i in range(0, len(n), 1):
        key += seed[int(n[i])]
    for j in range(0, len(r), 1):
        key += seed[int(r[j]) + 2]


# Our Log to the Console and file function
def LogToConsoleAndFile(the_message):
    # prints to the console
    # sets it to our file, writes it again, then puts stdout back.
    sys.stdout = orig_stdout
    print(the_message)
    sys.stdout = logFile
    # Print our Header to the File
    print(the_message)
    # Restore Output To Console
    sys.stdout = orig_stdout

# Resolve hostname, turn results or Null + 0
def hostname_resolves(hostname):
    try:
        hostip = socket.gethostbyname(hostname)
        return hostip, 1
    except socket.error:
        return "", 0

# Open and Create our LogFile
logFile = open(outputFilename, 'w')
sys.stdout = logFile
# LogToConsoleAndFile("Opened Our Output File")
# Script Kick Off
LogToConsoleAndFile("Get Categories for URLs from file")
# Print our Header to the File
LogToConsoleAndFile("# Instance: {}  | retrieved by user {} ###".format(cloudName, username))
# Get now time
logtimeStart = datetime.datetime.now()
LogToConsoleAndFile("# Script Started: {}\n".format(logtimeStart.strftime("%Y-%m-%d %H:%M:%S")))
LogToConsoleAndFile("Processing Script")
LogToConsoleAndFile(__file__)

# Obfuscate API Key
obfuscateApiKey()
# request structure to send to authenticate to admin UI with API Key
authentication = {"apiKey": key, "username": username, "password": password, "timestamp": now}
s = requests.session()
# authenticate to API portal
logon = s.post("https://admin.{0}.net/api/v1/authenticatedSession".format(cloudName), json=authentication)
if logon.status_code == 200:
    LogToConsoleAndFile("Logged in successfully in  API \n")
else:
    LogToConsoleAndFile("Could not log in API - reason %s \n") % (logon.status_code)
    sys.exit()

#########################################################################
#
#  This Chunk of code will read the target file and get classifications
#  for the URL n number of lines at a time.
#
#########################################################################

# Set how many lines we'll process at a time (MAX - 100)
linesAtATime = 100
apiCallNumber = 0

# Write our CSV Header
LogToConsoleAndFile("Results below this line is csv content. cut/copy/paste or open with Excel")
LogToConsoleAndFile("________________________________")
LogToConsoleAndFile(
    "url,dns_resolves,category_01,category_02,category_03,category_04,numCategories,secAlert_01,secAlert_02,secAlert_03,secAlert_04,numSecAlerts")

with open(urlsToCategorize) as file:
    while True:
        next_n_lines = list(islice(file, linesAtATime))
        strippedList = list(map(str.strip, next_n_lines))  # pull the \n chars off the list read from the file.
        if not next_n_lines:
            break
        data = {}
        data = strippedList
        json_data = json.dumps(data)  # Convert our data to json
        # Post to Zscaler via API
        results = s.post("https://admin.{0}.net/api/v1/urlLookup".format(cloudName), headers=headers, data=json_data)
        output = json.dumps(json.loads(results.text), indent=4, ensure_ascii=True)
        # Using JSON.Loads flattens to a list
        # Example: [{'url': '.amplitude.com', 'urlClassifications': ['CORPORATE_MARKETING', 'PROFESSIONAL_SERVICES'], 'urlClassificationsWithSecurityAlert': []}]
        responseStr: object = json.loads(output)
        # LogToConsoleAndFile(responseStr)
        listLen = len(responseStr)  # Get length of string (num items)
        # turn this flattened list into a csv string
        for x in range(0, listLen - 1):
            # Building our CSV String
            # URL, up-to (4) categories, and up-to (4) security events.
            csvString = ""
            # Add the url string (no Quotes) plus first delimiting comma
            csvString += responseStr[x]['url'] + ","
            # Check if this resolves...
            resolveTxt = ""
            if (len(responseStr[x]['url']) >= 1):
                hostresults, resolves = hostname_resolves(responseStr[x]['url'])
                if (resolves == 1):
                    resolveTxt = "YES:" + hostresults
                else:
                    resolveTxt = "DoesNotResolve"

            csvString += resolveTxt + ","

            # Add the "Categories"
            i = 0
            numberOfCategories = len(responseStr[x]["urlClassifications"])
            while i < numberOfCategories:
                csvString += responseStr[x]['urlClassifications'][i] + ","
                i += 1
            # Since there can be up-to 4 categories, we'll now add the missing delimiters
            if numberOfCategories == 0:
                csvString += ",,,,0,"
            if numberOfCategories == 1:
                csvString += ",,,1,"
            if numberOfCategories == 2:
                csvString += ",,2,"
            if numberOfCategories == 3:
                csvString += ",3,"
            # Add the Security Alerts
            i = 0
            numberOfSecurityAlerts = len(responseStr[x]["urlClassificationsWithSecurityAlert"])
            while i < numberOfSecurityAlerts:
                csvString += responseStr[x]['urlClassificationsWithSecurityAlert'][i] + ","
                i += 1
            # Since there can be up-to 4 security alerts, we'll now add the missing delimiters
            if numberOfSecurityAlerts == 0:
                csvString += ",,,,0"
            if numberOfSecurityAlerts == 1:
                csvString += ",,,1"
            if numberOfSecurityAlerts == 2:
                csvString += ",,2"
            if numberOfSecurityAlerts == 3:
                csvString += ",3"

            #
            # LogToConsoleAndFile(responseStr[x])
            LogToConsoleAndFile(csvString)

        time.sleep(1)  # pause to not over-run the API threshold of one per second
        apiCallNumber += 1
        # if apiCallNumber == 2:  # for debugging and testing.
        #    break

print("### Script is complete Examine Output AND REJOICE! ###")
print("### Buy Disher a glass of wine or a bourbon when you see him. ###")

# Loggingout
logoff = s.delete("https://admin.{0}.net/api/v1/authenticatedSession".format(cloudName))
if logoff.status_code == 200:
    LogToConsoleAndFile("\n\nLogged off successfully from API")
else:
    LogToConsoleAndFile("\n\nNot logged out from API")

logtimeEnd = datetime.datetime.now()
LogToConsoleAndFile("# Script Ended: {}\n".format(logtimeEnd.strftime("%Y-%m-%d %H:%M:%S")))
LogToConsoleAndFile("Script runtime approx: %f seconds" % (time.time() - start_time))
LogToConsoleAndFile("When you see Disher, buy him a drink because he just saved you a boat load of time.")

# Restore Stdout and close the logfile
sys.stdout = orig_stdout
logFile.close()
