import vt
import pscan

if __name__ == "__main__":
    file_path = "" # Enter path of the file
    vt_fscan = vt.VT_File_Scan(file_path)
    vt_uscan = vt.VT_URL_Scan() 
    process = pscan.Process()

    url = "https://youtube.com/" # Enter the URL
    uscan = vt_uscan.scan(url)
    rep = vt_uscan.url_analyse()

    process.control("curl.exe") # Enter the process