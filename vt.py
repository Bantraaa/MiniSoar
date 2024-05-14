import os
import sys
import time
import json
import requests
import argparse
import re
import hashlib
from bs4 import BeautifulSoup

class VT:
    def __init__(self):
        #VirusTotal API Key
        self.VT_API_KEY = "adaaedcc58e3262dc8b6106ec6f56d1e46c318d59886220733462ed43252fb7b"
        # VirusTotal API URL
        self.VT_API_URL = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey" : self.VT_API_KEY,
            "User-Agent" : "vtscan v.1.0",
            "Accept-Encoding" : "gzip, deflate",
        }

class VT_File_Scan(VT):
    def __init__(self):
        VT.__init__(self)

    #Uploading file to analyse
    def upload(self,file_path):
        upload_url = self.VT_API_URL + "files"
        files = {'file' : open(file_path , 'rb')}
        response = requests.post(upload_url, headers = self.headers, files = files)

        if response.status_code == 200:
            #Getting id of file
            upload_result = response.json()
            self.file_id = upload_result.get("data").get("id")
            return self.file_id
        else:
            return "ERROR"
    
    #Analysing file
    def analyse(self):
        analyse_url = self.VT_API_URL + "analyses/" + self.file_id
        response = requests.get(analyse_url, headers = self.headers)

        if response.status_code == 200:
            analyse_result = response.json()
            attr = analyse_result.get('data').get('attributes')

            if attr.get('status') == 'completed':
                status = attr.get('status')
                date = attr.get('date')
                results = attr.get('results')
                print("Malicious : " + str(attr.get('stats').get('malicious')))
                print("Undetected : " + str(attr.get('stats').get('undetected')))
                for res in results:
                    if results[res].get('category') == 'malicious':
                        print ("--------------------------------------------------")
                        print (results[res].get('engine_name'))
                        print ("version : " + str(results[res].get('engine_version', 'N/A')))
                        print ("category : " + results[res].get('category'))
                        print ("result : " + str(results[res].get('result', 'N/A')))
                        print ("method : " + results[res].get('method'))
                        print ("update : " + results[res].get('engine_update'))
                        print ("--------------------------------------------------\n")

            elif attr.get('status') == 'queued':
                with open(os.path.abspath(file_path), "rb") as f_path: #If status queued send file's hash to details
                    b = f_path.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    self.details(hashsum)

        else:
            print(response.status_code)

    #Analysing with hash of the file
    def details(self, file_hash):
        detail_url = self.VT_API_URL + "files/" + file_hash
        response = requests.get(detail_url, headers=self.headers)

        if response.status_code == 200:
            result = response.json()
            stats = result.get("data").get("attributes").get("last_analysis_stats")
            res = result.get("data").get("attributes").get("last_analysis_results")
            print("Malicious : " + str(stats.get('malicious')))
            print("Undetected : " + str(stats.get('undetected')) + "\n")

            for r in res:
                if res[r].get('category') == 'malicious':
                    print ("--------------------------------------------------")
                    print (res[r].get('engine_name'))
                    print ("version : " + res[r].get('engine_version'))
                    print ("category : " + res[r].get('category'))
                    print ("result : " + res[r].get('result'))
                    print ("method : " + res[r].get('method'))
                    print ("update : " + res[r].get('engine_update'))
                    print ("--------------------------------------------------\n")

class VT_URL_Scan(VT):
    def __init__(self):
        VT.__init__(self)

    #Scanning url
    def scan(self,target_url):
        payload = {"url": target_url}
        scan_url = self.VT_API_URL + "urls"
        response = requests.post(scan_url, headers = self.headers, data=payload)
        scan_result = response.json()

        #Return url id for analysing url
        if response.status_code == 200:
            self.url_id = str(scan_result.get('data').get('id')).split('-')[1]
            return self.url_id
        else:
            return "ERROR"
    
    def url_analyse(self):
        pattern = r"//(.*?)/"
        u_analyse_url = self.VT_API_URL + "urls/" + self.url_id
        response = requests.get(u_analyse_url, headers=self.headers)
        report = response.json()
        url_attr = report.get('data').get('attributes') #Attributes of URL analyse 
        url_stats = url_attr.get('last_analysis_stats') #Stats of URL analyse 
        url_results = url_attr.get('last_analysis_results')

        if response.status_code == 200:
            url = str(url_attr.get('url'))
            match = re.search(pattern, url)
            analysis_file_path = "C:\\Users\\HP\\Desktop\\VirusTotal\\"  # Specify your desired directory path here
            print(url.replace(':', '_'))
            with open(os.path.join(analysis_file_path, match.group(1) + "_analysis.txt"), "w+") as f:
                f.write("Malicious : " + str(url_stats.get('malicious')) + "\n")
                f.write("Suspicious : " + str(url_stats.get('suspicious')) + "\n")
                f.write("Harmless : " + str(url_stats.get('harmless')) + "\n")
                f.write("Undetected : " + str(url_stats.get('undetected')) + "\n")
                
                for ur in url_results:
                    if url_results[ur].get('category') == 'malicious':
                        f.write("--------------------------------------------------\n")
                        f.write(url_results[ur].get('engine_name') + "\n")
                        f.write("category : " + url_results[ur].get('category') + "\n")
                        f.write("result : " + url_results[ur].get('result') + "\n")
                        f.write("method : " + url_results[ur].get('method') + "\n")
                        f.write("--------------------------------------------------\n")
            
        else:
            return response.status_code        

if __name__ == "__main__": 
    vt_fscan = VT_File_Scan()
    vt_uscan = VT_URL_Scan()
    file_path = "C:\\Users\\HP\\Desktop\\MiniSoar\\HexToDec.cpp"
    scan_result = vt_fscan.upload(file_path)
    analyse = vt_fscan.analyse()
    print("Scan Result:", scan_result)

    #url = "https://youtube.com/"
    #uscan = vt_uscan.scan(url)
    #rep = vt_uscan.url_analyse()