import os
import socket
import httpx
import threading
import nmap


def harecker_host_recon(i,host_name):
    fwrite = open("result.txt", "a")
    host_ip = '1.1.1.1'
    http_response = ''
    https_response = ''
    nmap_result = ''
    nmap_list = []
    # ----------ping request
    try:
        response = os.system("ping -n 1 " + host_name)
        if response == 0:
            ping_result = 'Ping Up!'
        else:
            ping_result = 'Ping Down!'
    except:
        ping_result = 'Ping request could not find host'

    # ----------resolve IP
    try:
        host_ip = socket.gethostbyname(host_name)
    except:
        host_ip = "host ip resolve with error"
    # ----------HTTP Req

    try:
        url='http://' + host_name
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36.'}
        client = httpx.Client(headers=headers)
        r = client.get(url)
        http_response = str(r.status_code) + ' ' + r.reason_phrase + "  |  " + str(r.request) + " | " + "is_client_error = " + str(r.is_client_error) + " ; " + "is_closed = " + str(r.is_closed) + " ; " + "is_error = " + str(r.is_error) + " ; " + "is_informational = " + str(r.is_informational) + " ; " + "is_redirect = " + str(r.is_redirect) + " ; " + "is_server_error = " + str(r.is_server_error)  + ' | Redirection to : ' + str(r.next_request)

    except httpx.RequestError as err:
        http_response = str(err) + ' | For: ' + str(err.request) + " |  " + " |  "


    # ----------HTTPS Req
    try:
        url='https://' + host_name
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36.'}
        client = httpx.Client(headers=headers)
        r = client.get(url)
        https_response = str(r.status_code) + ' ' + r.reason_phrase + " |  " + str(r.request) + " | " + "is_client_error = " + str(r.is_client_error) + " ; " + "is_closed = " + str(r.is_closed) + " ; " + "is_error = " + str(r.is_error) + " ; " + "is_informational = " + str(r.is_informational) + " ; " + "is_redirect = " + str(r.is_redirect) + " ; " + "is_server_error = " + str(r.is_server_error)  + ' | Redirection to : ' + str(r.next_request)

    except httpx.RequestError as err:
        https_response = str(err) + ' | For: ' + str(err.request) +  " |  " + " |  "

# -------------NMAP
    if nmap_list.__contains__(host_ip):
        nmap_result = "NMAP Done Before!! "
    else:
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=host_name, arguments='-A --top-ports 1000 -T5 -Pn')
            nmap_list.append(host_ip)

            nm_result = nm._scan_result['scan'].popitem()
            osstr = nm_result[1]['osmatch']
            portstr = nm_result[1]['tcp']
            statestr = nm_result[1]['status']

            nmap_result = str(osstr[0]) + ' | ' + str(portstr) + ' | ' + str(statestr);

        except:
            nmap_result = "NMAP Scan ERROR!! "

    final_result = str(i) + ' | ' + host_name + ' | ' + host_ip + ' | ' + ping_result + ' | ' + http_response + ' | ' + https_response + ' | ' + nmap_result + '\n'
    fwrite.write(final_result)
    return

input_file=input("please input txt file contains target hostname(s)\r\n")
fread = open(input_file, "r")
x = len(fread.readlines())
fread = open(input_file, "r")

open('result.txt', 'w').close()
fwrite = open("result.txt", "a")
fwrite.write("# |   Target Host   |  Target IP   | Ping Status |   HTTP Response Code   |   HTTP GET Request   |   HTTP_DETAILS   |   HTTP_REDIRECTION   |   HTTPS Response Code   |   HTTPS GET REQUEST   |   HTTPS_DETAILS   |   HTTPS_REDIRECTION   |   NMAP_OS   |   NMAP_PORT   |   NMAP_HOST_STATE   \n")
fwrite.close()
host_name = "a"
i = 0

while len(host_name) != 0:
    print("[---------------process: " + str((i/x)*100) + "---------------]")
    i += 1
    host_name = fread.readline()
    host_name = host_name.replace('\n', '')
    t1 = threading.Thread(target=harecker_host_recon, args=(i,host_name,))
    i += 1
    host_name = fread.readline()
    host_name = host_name.replace('\n', '')
    t2 = threading.Thread(target=harecker_host_recon, args=(i,host_name,))
    i += 1
    host_name = fread.readline()
    host_name = host_name.replace('\n', '')
    t3 = threading.Thread(target=harecker_host_recon, args=(i,host_name,))
    i += 1
    host_name = fread.readline()
    host_name = host_name.replace('\n', '')
    t4 = threading.Thread(target=harecker_host_recon, args=(i,host_name,))
    i += 1
    host_name = fread.readline()
    host_name = host_name.replace('\n', '')
    t5 = threading.Thread(target=harecker_host_recon, args=(i,host_name,))
    # starting thread 1
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()

    # wait until thread 1 is completely executed
    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()

fwrite.close()
