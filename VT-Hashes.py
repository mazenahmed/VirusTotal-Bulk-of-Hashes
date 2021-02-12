import requests
import csv
import time
from pyfiglet import figlet_format


def check_hash(hash):
    '''
    this method communicates with VT API
    and reterive security controls report
    '''
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource':str(hash)}
    response = requests.get(url, params=params)
    if(response.status_code == 200):
        return response.json()
    else:
        #print(response.status_code)
        return hash


def reanalyze(hash):
    '''
    this method communicates with VT API and reanalyzing the passed hash
    '''
    url='https://www.virustotal.com/api/v3/files/{0}/analyse'.format(hash)
    headers = {'x-apikey': apikey}
    response = requests.post(url, headers=headers)
    if(response.status_code == 200):
        return
        #print(response.json()['data']['type'] + "   " + hash)
    elif(response.status_code == 404) :
        return
        print ("Hash Not found: {0}".format(hash))
    elif(response.status_code == 429):
        print("You've Exceeded yout qouta: {0}".format(hash))
    else:
        print("Conectivity Error: {0} {1}".format(response.status_code,hash))


apikey= input('Enter your API KEY: ')

'''
first step:
    reanalyze All the hash
'''
print(figlet_format("REANALYZING PHASE"))
with open('bulk.csv', mode='r') as csv_bulk:
    bulk_read = csv.reader(csv_bulk,delimiter=',')
    requestNumber = 1
    for row in bulk_read:
        for column in row:
            diff=64-len(column)
            print("Reanalyzing {0}".format(column)," "*diff ,end="",flush=True)
            print("\r",end="",flush=True)
            if column:
                reanalyze(column)

            time.sleep(15)
    print()

cnt=10
print("Next Phase Is Going to Start", end="",flush=True)
while True:
    if cnt >= 300:
        break
    print(end=".",flush=True)
    time.sleep(10) # waiting 5 min for analyzing process to be done
    cnt+=10

print()
'''
second step:
    Check every single hash if detected or just UNKNOWN
'''
print(figlet_format("DETECTING PHASE"))
with open('bulk.csv', mode='r') as csv_bulk:
    bulk_read = csv.reader(csv_bulk,delimiter=',')
    output=open("results.csv","w+")
    filewriter = csv.writer(output,delimiter=',',quotechar='|')
    filewriter.writerow(['HASH','#DetectedEngines'])
    for row in bulk_read:
        for column in row:

            if column:

                diff=64-len(column)
                print("Checking {0}".format(column)," "*diff ,end="",flush=True)
                print("\r",end="",flush=True)
                resp = check_hash(column)

                if resp == column:
                    print ("network error   " + column)
                    
                elif int(resp["response_code"]) != 0:
                    res=str(resp["positives"]) + '/' + str(resp['total'])  
                    filewriter.writerow([column,res])

                else:
                    #not detected by any Engines
                    filewriter.writerow([column,"UNKNOWN"])

                time.sleep(15)
    print()
    output.write('\n')
    output.close()
    print(figlet_format("BYE BYE"))
    print("Written By Mazen A. Gaballah")




