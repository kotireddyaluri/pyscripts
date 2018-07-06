import nmap
import json
import pymongo
import sys
import os
import socket
from pymongo import MongoClient

client = MongoClient('159.65.145.67', 27017)
hostname= sys.argv[1]
ports = "7, 11, 13, 15, 17, 19, 21, 22, 23, 25, 26, 37, 49, 53, 67, 69, 70, 79, 80, 81, 82, 83, 84, 88, 102, 110, 111, 119, 123, 129, 137, 143, 161, 175, 179, 195, 311, 389, 443, 444, 445, 465, 500, 502, 503, 515, 520, 523, 554, 587, 623, 626, 631, 636, 666, 771, 789, 873, 902, 992, 993, 995, 1010, 1023, 1025, 1099, 1177, 1200, 1234, 1311, 1434, 1471, 1604, 1723, 1777, 1883, 1900, 1911, 1962, 1991, 2000, 2067, 2082, 2083, 2086, 2087, 2123, 2152, 2181, 2222, 2323, 2332, 2375, 2376, 2404, 2455, 2480, 2628, 3000, 3128, 3306, 3386, 3388, 3389, 3460, 3541, 3542, 3689, 3749, 3780, 3784, 3790, 4000, 4022, 4040, 4063, 4064, 4070, 4369, 4443, 4444, 4500, 4567, 4800, 4848, 4911, 4949, 5000, 5001, 5006, 5007, 5008, 5009, 5060, 5094, 5222, 5269, 5353, 5357, 5432, 5555, 5560, 5577, 5632, 5672, 5683, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6664, 6666, 6667, 6881, 6969, 7071, 7218, 7474, 7547, 7548, 7657, 7777, 7779, 8000, 8010, 8060, 8069, 8080, 8081, 8086, 8087, 8089, 8090, 8098, 8099, 8112, 8139, 8140, 8181, 8333, 8334, 8443, 8554, 8649, 8834, 8880, 8888, 8889, 9000, 9001, 9002, 9051, 9080, 9100, 9151, 9160, 9191, 9200, 9418, 9443, 9595, 9600, 9943, 9944, 9981, 9999, 10000, 10001, 10243, 11211, 12345, 13579, 14147, 16010, 17000, 18245, 20000, 20547, 21025, 21379, 23023, 23424, 25105, 25565, 27015, 27017, 28017, 30718, 32400, 32764, 37777, 44818, 47808, 48899, 49152, 49153, 50070, 50100, 51106, 55553, 55554, 62078, 64738"
try:
	host=socket.gethostbyname(hostname)
except:
	print "[ERR]:host not reachable"
else:

	#scan using nmap
	nm = nmap.PortScanner()
	scanRes = nm.scan(host, ports)
	print "[INFO]:nmap scan done for "+hostname+"--["+host+"]"

	#parse json data
	jsonScanRes=json.dumps(scanRes)
	jsonResult=json.loads(jsonScanRes)

	#insert json into mongodb (collectionName=nmapRes)
	nmap_db= client.test
	nmap_collection = nmap_db.nmapRes
	nmap_collection.insert(jsonResult,check_keys=False)
	print "[INFO]:saved.. Done!"
	
	#Running dirsearch and save it in mongodb(collection=dirSearchReport)
	os.system("python3 ~/tools/dirsearch/dirsearch.py -e php,asp,aspx,jsp,html,zip,jar,sql -u "+hostname+" --json-report=dir_report_"+hostname+".json")
	
	#reading dirsearch json report
	dir_report=open("dir_report_"+hostname+".json", 'r')
	json_dir_report=json.dumps(dir_report.read())
	dir_report_pjson=json.loads(json_dir_report)
	dir_reportJson = json.loads(dir_report_pjson)
	
	#insert json into mongodb
	dir_report_collection = nmap_db.dirSearchReport
	dir_report_collection.insert(dir_reportJson,check_keys=False)
	print "[INFO]: dirsearch results saved!"
