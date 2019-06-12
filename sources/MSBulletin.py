#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for Microsoft Bulletin information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016-2017    Pieter-Jan Moreels - pieterjan.moreels@gmail.com
# Copyright (c) 2017         Hicham MEGHERBI  
# Copyright (c) 2017         Conix

# Imports
import gzip
import json
import requests
import os
from lib.Config  import Configuration as conf

from collections import defaultdict

from lib.Source import Source

SOURCE_NAME = "msbulletin"
MSRCAPIURL = "https://api.msrc.microsoft.com"
SOURCE_FILE = MSRCAPIURL + "/Updates"
API_VERSION = '2016-08-01'
CURRENT_PATH = os.path.dirname(os.path.realpath(__file__))
GZIP_FILE   = os.path.join(CURRENT_PATH,"../data/old_Microsoft_bulletins.gz")

# update based on code here
# https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API
#

def get_Old_Bulletins():
    try:
        data = gzip.open( GZIP_FILE, "rb" ).read()
        return json.loads( data.decode("utf-8") )
    except Exception as e:
        print("Could not read old Bulletins")
        return {}

def clean_date(_, item):
    if _.get(item): _[item] = _[item].split('T')[0]

def get_msbulletin(url):
    """
    Query the documented MSRC public API to fetch all the bulletins
    and related data.
    Select all the bulletins .
    Return a list of dictionaries with this structure:
    Data input

      url: url of  microsoft
      form_date: start date
      to_date: end date

    get_msbulletin(url, from_date= "01/01/1900" , to_date= None) -> json

     {
      "publishedDate": "2017-05-09T07:00:00",
      "cveNumber": "CVE-2017-0279",
      "cveUrl": "https://portal.msrc.microsoft.com/en-US/security-guidance/
      advisory/CVE-2017-0279",
      "name": "Windows Server 2008 for x64-based Systems Service Pack 2",
      "platform": null,
      "family": "Windows",
      "impactId": 1,
      "impact": "Remote Code Execution",
      "severityId": 1,
      "severity": "Critical",
      "knowledgeBaseId": "4018466",
      "knowledgeBaseUrl": "https://support.microsoft.com/help/4018466",
      "monthlyKnowledgeBaseId": "",
      "monthlyKnowledgeBaseUrl": null,
      "downloadUrl": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB4018466",
      "monthlyDownloadUrl": null
    },
    """
    api_key = conf.readSetting("msbulletin", "api_key", "")
    headers = {
        'Accept': "application/json, text/plain, */*",
        'Content-Type': 'application/json;charset=utf-8',
        'api-key': api_key
    }


    # query = {
    #     'familyIds': [], 'productIds': [], 'severityIds': [], 'impactIds': [],
    #     'pageNumber': 1, 'pageSize': 50000,
    #     'includeCveNumber': True, 'includeSeverity': True, 'includeImpact': True,
    #     'orderBy': 'publishedDate', 'orderByMonthly': 'releaseDate',
    #     'isDescending': True, 'isDescendingMonthly': True,
    #     'queryText': '', 'isSearch': False, 'filterText': '',
    #     'fromPublishedDate': from_date
    # }
    query = {
        'api-version' : API_VERSION
    }


    # if to_date:
    #     query['toPublishedDate'] = to_date

    get = requests.get(url, headers=headers, params=query)

    blist = get.json().get("value",[])

    products = []
    product_by_id = {}
    product_branches = {}
    vulnerabilities = []
    vendor_branches = {}

    for blisti in blist:
        if "CvrfUrl" in blisti:
            cvrfdoc = requests.get(blisti["CvrfUrl"], headers=headers).json()
            if "ProductTree" in cvrfdoc:
                if "Branch" in cvrfdoc["ProductTree"]:
                    for branchi in cvrfdoc["ProductTree"]["Branch"]:
                        if "Items" in branchi:
                            vendor_branches[branchi["Name"]] = {"Type":branchi["Type"]}
                            for producti in branchi["Items"]:
                                product_branches[producti["Name"]] = {"Type": producti["Type"]}
                                for productdeti in producti.get("Items",[]):
                                    if productdeti["ProductID"] not in product_by_id:
                                        prodpos = len(products)
                                        productdeti["ProductBranch"] = producti["Name"]
                                        productdeti["VendorBranch"] = branchi["Name"]
                                        products.append(productdeti)
                                        product_by_id[productdeti["ProductID"]] = prodpos
                if "FullProductName" in cvrfdoc["ProductTree"]:
                    for prodi in cvrfdoc["ProductTree"]["FullProductName"]:
                        if prodi["ProductID"] not in product_by_id:
                            prodpos = len(products) + 1
                            products.append(producti)
                            product_by_id[prodi["ProductID"]] = prodpos
            if "Vulnerability" in cvrfdoc:
                for vuli in cvrfdoc["Vulnerability"]:
                    vulnerabilities.append(vuli)
    return vulnerabilities, products, product_by_id, product_branches

class MSBulletin(Source):

    """
      Get msbulletins & Add all CVEs found in VIA4CVE.feed.json

       "CVE-2017-0072": {
          "msbulletin": [
            {
              "kb_id": "4012583",
              "title": "Windows Server 2008 for x64-based Systems Service Pack 2",
              "knowledgebase_SOURCE_FILE": "https://support.microsoft.com/en-us/kb/4012583",
              "severity": "Critical",
              "impact": "Remote Code Execution",
              "knowledgebase_id": "4012583",
              "cves_url": "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0072",
              "date": "2017-03-14T07:00:00",
              "bulletin_SOURCE_FILE": "https://portal.msrc.microsoft.com/api/security-guidance/en-us/"
            }
          ]
        },

    """

    def __init__(self):
        self.name = SOURCE_NAME
        vulnerabilities, products, product_by_id, product_branches = get_msbulletin(SOURCE_FILE)  # Get MS Bulletins in Json Format
        mskb = defaultdict(dict)
        old  = get_Old_Bulletins()
        self.cves = defaultdict(list)

        sevs = {"Unknown":-1,
                "None":0,
                "Low":1,
                "Moderate":2,
                "Important":3,
                "Critical":4
        }

        for entry in vulnerabilities:

            cve_number = entry['CVE']

            for product in entry['ProductStatuses']:
                for productId in product["ProductID"]:
                    mskb[cve_number]['published'] = entry['RevisionHistory'][0]["Date"]  # PublishedDate

                    clean_date(mskb[cve_number],'published')

                    mskb[cve_number]['knowledgebase_id'] = entry['CVE']  # KB id

                    # taken from https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/master/src/MsrcSecurityUpdates/Public/Get-MsrcCvrfCVESummary.ps1
                    severity = "Unknown"
                    for threati in entry["Threats"]:
                        if threati["Type"] == 3:
                            if sevs[threati["Description"]["Value"]] > sevs[severity]:
                                severity = threati["Description"]["Value"]

                    mskb[cve_number]['severity'] = severity

                    # taken from https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API/blob/master/src/MsrcSecurityUpdates/Public/Get-MsrcCvrfCVESummary.ps1
                    impact = "Unknown"
                    for threati in entry["Threats"]:
                        if threati["Type"] == 0:
                            impact = threati["Description"]["Value"]

                    mskb[cve_number]['impact'] = impact
                    mskb[cve_number]['title'] = entry["Title"].get("Value","")
                    description = ""
                    for notei in entry["Notes"]:
                        description = description + notei["Title"]+":"+notei["Value"]
                    mskb[cve_number]['description'] = description
                    mskb[cve_number]['name'] = products[product_by_id[productId]].get("Value","")  # Product Name
                    mskb[cve_number]['cves'] = entry['CVE']  # CVE  id
                    mskb[cve_number]['cves_url'] = "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/{}".format(entry['CVE'] ) # CVE url

                    mskb[cve_number]['bulletin_SOURCE_FILE'] = SOURCE_FILE
                    # mskb[cve_number]['knowledgebase_SOURCE_FILE'] = entry['knowledgeBaseUrl']  # File source of KB

        for _id, data in mskb.items():
            data_cves = data.pop("cves")

            # bulletins = old.get(data_cves, [])
            #mskb_ids = [x['knowledgebase_id'] for x in bulletins]
            #if data['knowledgebase_id'] not in mskb_ids:
            #    mskb_ids.append(data['knowledgebase_id'])
            bulletins = data
            if data_cves:
                self.cves[data_cves] = [bulletins]

        for _id,data in old.items():
            if _id not in self.cves:
                self.cves[_id] = data


    def cleanUp(self, cveID, cveData):
        if cveData.get('refmap', {}).get('ms'):
            del cveData['refmap']['ms']

    def getSearchables(self):
        return ['name', 'knowledgebase_id']
