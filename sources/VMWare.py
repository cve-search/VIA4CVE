#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Source file for Microsoft Bulletin information
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016    Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Sources
SOURCE_NAME = 'vmware'
SOURCE_FILE = "https://www.vmware.com/files/xls/security/VMWareSecurityAdvisoryList.xlsx"

# Imports
import copy
import datetime
import xlrd

from collections import defaultdict

from lib.Config  import Configuration as conf
from lib.Source  import Source

workbook_format = wf = {'cve':             8,   'workaround':     14,
                        'advisory_id':    10,   'finder_company': 15,
                        'advisory_url':   11,   'finder_name':    16,
                        'title':          12,   'published':      19,
                        'description':    13,   'last_updated':   20}
                        # URL currently missing as xlrd does not support
                        #  function extraction, and the workbook uses a function

def minimalist_xldate_as_datetime(xldate, datemode):
    # datemode: 0 for 1900-based, 1 for 1904-based
    if type(xldate) == str: return datetime.datetime.strptime(xldate, "%d/%m/%Y").date()
    return (datetime.datetime(1899, 12, 30)
            + datetime.timedelta(days=xldate + 1462 * datemode))

class VMWare(Source):
  def __init__(self):
    self.name = SOURCE_NAME
    _file, r  = conf.getFeedData(SOURCE_NAME, SOURCE_FILE, unpack=False) # Don't unpack, 'cuz XLSX's are zips
    workbook  = xlrd.open_workbook(file_contents = _file)
    worksheet = workbook.sheet_by_index(0)
    vmware    = defaultdict(lambda : defaultdict(dict))
    self.cves = defaultdict(list)

    for rownum in range(worksheet.nrows-1): # -1 because we skip the header
      row = worksheet.row_values(rownum+1)  # +1 because we skip the header
      # Convert date to date object
      published   = minimalist_xldate_as_datetime(row[wf['published']],    0).isoformat()
      last_update = minimalist_xldate_as_datetime(row[wf['last_updated']], 0).isoformat()

      for cve in row[wf['cve']].split(";"):
        cve = cve.strip()
        # skip if exists
        if row[wf['advisory_id']] in vmware[cve].keys():
          continue

        vmware[cve][row[wf['advisory_id']]]['id']           = row[wf['advisory_id']]
        vmware[cve][row[wf['advisory_id']]]['title']        = row[wf['title']]
        vmware[cve][row[wf['advisory_id']]]['description']  = row[wf['description']]
        vmware[cve][row[wf['advisory_id']]]['published']    = published
        vmware[cve][row[wf['advisory_id']]]['last_updated'] = last_update
        if row[wf['workaround']] not in ["NA", "N/A", ""]:
          vmware[cve][row[wf['advisory_id']]]['workaround'] = row[wf['workaround']]

        finder = {}
        if row[wf['finder_company']] not in ["NA", "N/A", ""]:
          finder['company'] = row[wf['finder_company']]
        if row[wf['finder_name']]    not in ["NA", "N/A", ""]:
          finder['name']    = row[wf['finder_name']]
        if len(finder.keys()) is not 0:
          vmware[cve][row[wf['advisory_id']]]['finder']     = finder

    for cve, data in vmware.items():
      for _id, _data in data.items():
        self.cves[cve].append(_data)
