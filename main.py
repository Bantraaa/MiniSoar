import vt
import pscan


if __name__ == "__main__":
    file_path = "C:\\Users\\HP\\Desktop\\MiniSoar\\HexToDec.cpp"
    vt_fscan = vt.VT_File_Scan(file_path)
    vt_uscan = vt.VT_URL_Scan()
    process = pscan.Process()
    scan_result = vt_fscan.upload()
    analyse = vt_fscan.analyse()

    url = "https://facebook.com/"
    uscan = vt_uscan.scan(url)
    rep = vt_uscan.url_analyse()

    #process.control("curl.exe")