import pyshark 
import requests
from ipaddress import ip_address
import json
import sys

input_file = sys.argv[1]
pcap_file = pyshark.FileCapture(input_file) # path to PCAP file
api_key = str(sys.argv[2])  # API Key
traffic_type = str(sys.argv[3])  # Type of traffic

#HTTP

def http_requests():

    test_list1 = []
    test_list2 = []


    for pkt in pcap_file:
        try:
            if "HTTP" in pkt:
                test_list1.append(
                    "A " + pkt.http.request_method + " request was made to resource " + pkt.http.request_uri + " at host " + pkt.http.host)
                test_list2 = sorted(set(test_list1))
        except AttributeError:
            pass
    for x in test_list2:
        print(x + "\n")


def domain_check_VT(domain):
    urld = "https://www.virustotal.com/api/v3/domains/"
    headers = {"accept": "application/json",
               "x-apikey": api_key}

    vurld = urld + str(domain)
    response = requests.get(vurld, headers=headers)
    response_json = json.loads(response.content)
    try:

        if (response_json['data']['attributes']['last_analysis_stats']['malicious'] or
            response_json['data']['attributes']['last_analysis_stats']['suspicious']) > 0:
            print(str(domain) + " has " + str(
                response_json['data']['attributes']['last_analysis_stats']['malicious']) + " malicious hit(s)")

    except KeyError:
        print("You may have exceeded your VirusTotal API QUOTA or API-KEY may be invalid")

def http_host_VTCheck():
    list1 = []
    list2 = []

    for pkt in pcap_file:
        try:
            if "HTTP" in pkt:
                list1.append(pkt.http.host)
                list2 = sorted(set(list1))
        except AttributeError:
            pass

    for value in list2:
        domain_check_VT(value)

#TCP

def count_for_malicious_ip(ip):

    url = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {"accept": "application/json",
               "x-apikey": api_key
               }

    vurl = url + str(ip)
    response = requests.get(vurl, headers=headers)
    response_json = json.loads(response.content)
    if (response_json['data']['attributes']['last_analysis_stats']['malicious']) > 0:
        count = (str(ip) + " has " + str(
            response_json['data']['attributes']['last_analysis_stats']['malicious']) + " malicious hit(s)")
        print(count)
    elif (response_json['data']['attributes']['last_analysis_stats']['suspicious']) > 0:
        count = (str(ip) + " has " + str(
            response_json['data']['attributes']['last_analysis_stats']['suspicious']) + " suspicious hit(s)")
        print(count)

def is_connection_to_ip_malicious(ip):  # need for TCP query

    url = "https://www.virustotal.com/api/v3/ip_addresses/"
    headers = {"accept": "application/json",
               "x-apikey": api_key
               }

    vurl = url + str(ip)
    response = requests.get(vurl, headers=headers)
    response_json = json.loads(response.content)
    if (response_json['data']['attributes']['last_analysis_stats']['malicious'] or
        response_json['data']['attributes']['last_analysis_stats']['suspicious']) > 0:
        return True

    return False

def collect_unique_public_ip(pcap):
    total_ip = []
    sorted_ip = []
    non_private_ip = []
    for pkt in pcap:
        if "TCP" in pkt:
            total_ip.append(pkt.ip.src)
            total_ip.append(pkt.ip.dst)

    for address in total_ip:
        a = ip_address(address)
        if not a.is_private:
            non_private_ip.append(a)
            sorted_ip = sorted(set(non_private_ip))
    return sorted_ip

def malicious_connections_to_public_ip():
    for ip in collect_unique_public_ip(pcap_file):  # ip has to be public
        if (is_connection_to_ip_malicious(ip)):
            str(count_for_malicious_ip(ip))

#DNS

def count_for_malicious_domain(domain):
    urld = "https://www.virustotal.com/api/v3/domains/"
    headers = {"accept": "application/json",
               "x-apikey": api_key}

    vurld = urld + str(domain)
    response = requests.get(vurld, headers=headers)
    response_json = json.loads(response.content)

    if (response_json['data']['attributes']['last_analysis_stats']['malicious']) > 0:
        count = (str(domain) + " has " + str(
            response_json['data']['attributes']['last_analysis_stats']['malicious']) + " malicious hit(s)")
        print(count)
    elif (response_json['data']['attributes']['last_analysis_stats']['suspicious']) > 0:
        count = (str(domain) + " has " + str(
            response_json['data']['attributes']['last_analysis_stats']['suspicious']) + " suspicious hit(s)")
        print(count)

def dns_queries_and_responses():
    list4 = []
    list5 = []
    for pkt in pcap_file:
        try:
            if "DNS" in pkt:
                a = ip_address(pkt.dns.a)
                if (a.is_private):
                    continue
                list4.append("A DNS query was made for " + str(pkt.dns.qry_name) + " that resolved to: " + str(
                    pkt.dns.a) + ".")
                list5 = sorted(set(list4))

        except AttributeError:
            pass

    print("********************QUERIES************" + "\n")

    for value in list5:
        print(value + "\n")

    print("********************DOMAINS************" + "\n")

    for value in list5:
        try:

            domain = value.partition("for")[2]
            domain_text = str(domain.partition("that")[-3]).replace(" ", "")
            str(count_for_malicious_domain(domain_text))

        except KeyError:
            print("You may have exceeded your VirusTotal API QUOTA or API-KEY may be invalid")

    print("********************IPs************" + "\n")

    for value in list5:
        try:

            ip_text = str(value.partition(":")[2]).replace(" ", "")
            str(count_for_malicious_ip(ip_text))

        except KeyError:
            print("You may have exceeded your VirusTotal API QUOTA or API-KEY may be invalid")



#TCP AND UDP PAYLOAD

def isascii(s):  # checks if string is ascii
    return len(s) == len(s.encode())

def tcp_payload():

    hexcode_list = []  # list containing hexcodes
    cleaned_hexcode_list = []
    decoded_list = []  # list containg decoded hexcodes
    final_list = []  # list containing readable ascii characters
    for pkt in pcap_file:
        char = ":"
        try:
            if "TCP" in pkt:
                hexcode_list.append(pkt.tcp.payload)
                cleaned_hexcode_list = [i.replace(char, '') for i in hexcode_list]
        except AttributeError:
            pass
        except ValueError:
            pass

    for value in cleaned_hexcode_list:
        try:
            decoded_string = bytes.fromhex(value).decode('utf-8', errors='ignore')
            decoded_list.append(decoded_string)
        except ValueError:
            pass

    for a in decoded_list:
        try:
            if (isascii(a)):
                final_list.append(a)
        except ValueError:
            pass

    for b in final_list:
        print(b)


def udp_payload():

    hexcode_list = []  # list containing hexcodes
    cleaned_hexcode_list = []
    decoded_list = []  # list containg decoded hexcodes
    final_list = []  # list containing readable ascii characters
    for pkt in pcap_file:
        char = ":"
        try:
            if "UDP" in pkt:
                hexcode_list.append(pkt.udp.payload)
                cleaned_hexcode_list = [i.replace(char, '') for i in hexcode_list]
        except AttributeError:
            pass
        except ValueError:
            pass

    for value in cleaned_hexcode_list:
        try:
            decoded_string = bytes.fromhex(value).decode('utf-8', errors='ignore')
            decoded_list.append(decoded_string)
        except ValueError:
            pass

    for a in decoded_list:
        try:
            if (isascii(a)):
                final_list.append(a)
        except ValueError:
            pass

    for b in final_list:
        print(b)



#Starter

def initialize():

    if (str(traffic_type) == "1"):
        print("\n")
        print("HTTP REQUESTS")
        http_requests()
        print("\n")
        print(("Domain analysis with VirusTotal"))
        http_host_VTCheck()

    elif (str(traffic_type) == "2"):
        dns_queries_and_responses()

    elif (str(traffic_type) == "3"):
        print("Malicious TCP connections observed" + "\n")
        malicious_connections_to_public_ip()

    elif (str(traffic_type) == "4"):
        print("CHECKING FOR HTTP, DNS, and TCP")
        print("HTTP" + "\n")
        http_requests()
        http_host_VTCheck()
        print("DNS" + "\n")
        dns_queries_and_responses()
        print("TCP" + "\n")
        malicious_connections_to_public_ip()

    elif (str(traffic_type) == "5"):
        print("TCP payload" + "\n")
        tcp_payload()

    elif (str(traffic_type) == "6"):
        print("UDP payload" + "\n")
        udp_payload()

    else:
        print("Input not supported, please try again")

initialize()













  
