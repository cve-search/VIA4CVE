#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for Microsoft Bulletin information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com
# Copyright (c) 2017    Hicham MEGHERBI  
# Copyright (c) 2017    Conix

# Imports
import json
from collections import defaultdict

import requests

from lib.Source import Source

SOURCE_NAME = "msbulletin"
SOURCE_FILE = "https://portal.msrc.microsoft.com/api/security-guidance/en-us/"


def get_msbulletin(url, from_date='01/01/1900', to_date=None):
    """
    Query the undocumented MSRC public API to fetch all the bulletins
    and related data.
    Select all the bulletins between `from_date` and `to_date`.
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
    headers = {
        'Accept': "application/json, text/plain, */*",
        'Content-Type': 'application/json;charset=utf-8',
        'Referer': 'https://portal.msrc.microsoft.com/en-us/security-guidance'
    }

    query = {
        'familyIds': [], 'productIds': [], 'severityIds': [], 'impactIds': [],
        'pageNumber': 1, 'pageSize': 50000,
        'includeCveNumber': True, 'includeSeverity': True, 'includeImpact': True,
        'orderBy': 'publishedDate', 'orderByMonthly': 'releaseDate',
        'isDescending': True, 'isDescendingMonthly': True,
        'queryText': '', 'isSearch': False, 'filterText': '',
        'fromPublishedDate': from_date
    }

    if to_date:
        query['toPublishedDate'] = to_date

    post = requests.post(url, headers=headers, data=json.dumps(query))
    if post:
        return post.json()
    else:
        return {}


class MSBulletin_V2(Source):

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
        data_json = get_msbulletin(SOURCE_FILE)  # Get MS Bulletins in Json Format
        mskb = defaultdict(dict)
        self.cves = defaultdict(list)

        for entry in data_json['details']:

            cve_number = entry['cveNumber']

            mskb[cve_number]['publishedDate'] = entry['publishedDate']  # PublishedDate
            mskb[cve_number]['knowledgebase_id'] = entry['knowledgeBaseId']  # KB id
            mskb[cve_number]['severity'] = entry['severity']
            mskb[cve_number]['impact'] = entry['impact']
            mskb[cve_number]['name'] = entry['name']  # Product Name
            mskb[cve_number]['cves'] = entry['cveNumber']  # CVE  id
            mskb[cve_number]['cves_url'] = entry['cveUrl']  # CVE url

            mskb[cve_number]['bulletin_SOURCE_FILE'] = SOURCE_FILE
            mskb[cve_number]['knowledgebase_SOURCE_FILE'] = entry['knowledgeBaseUrl']  # File source of KB

        for _id, data in mskb.items():
            data_cves = data.pop("cves")
            if data_cves:
                self.cves[data_cves].append(data)

    def cleanUp(self, cveID, cveData):
        if cveData.get('refmap', {}).get('ms'):
            del cveData['refmap']['ms']

    def getSearchables(self):
        return ['name', 'knowledgebase_id']
