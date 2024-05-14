import os
import sys
import time
import json
import requests
import argparse
import re
import hashlib
from bs4 import BeautifulSoup
import vt
import pscan

if __name__ == "__main__":
    vt_fscan = vt.VT_File_Scan()
    vt_uscan = vt.VT_URL_Scan()
    process = pscan.Process()
    file_path = "C:\\Users\\HP\\Desktop\\VirusTotal\\HexToDec.cpp"
    #scan_result = vt_fscan.upload(file_path)
    #analyse = vt_fscan.analyse()
    #print("Scan Result:", scan_result)

    #url = "https://youtube.com/"
    #uscan = vt_uscan.scan(url)
    #rep = vt_uscan.url_analyse()

    process.control("curl.exe")