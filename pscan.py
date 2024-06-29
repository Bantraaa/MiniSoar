
import requests
from bs4 import BeautifulSoup

class Process:
    def __init__(self):
        self.url = "https://www.file.net/process/"
    
    def control(self, process):
        request_url = self.url + process + ".html"
        response = requests.get(request_url)
        soup = BeautifulSoup(response.content, "html.parser")
        section = soup.find("h1").parent  #Selceting h1 as parent
        selected_text = section.get_text()
        print(selected_text)