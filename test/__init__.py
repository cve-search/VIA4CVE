import traceback

tests = {'D2sec':            {'cve': 'CVE-2009-3534', 'key': "d2sec.%.name",                'val': "LionWiki 3.0.3 LFI"},
         'ExploitDB':        {'cve': 'CVE-2009-4186', 'key': "exploit-db.%.id",             'val': "10102"},
         'IAVM':             {'cve': 'CVE-2007-0214', 'key': "iavm.id",                     'val': "2007-A-0014"},
         'MSBulletin':       {'cve': 'CVE-2016-7241', 'key': "msbulletin.%.bulletin_id",    'val': "MS16-142"},
         'OVAL':             {'cve': 'CVE-2007-5730', 'key': "oval.%.id",                   'val': "oval:org.mitre.oval:def:10000"},
         'RedHatInfo':       {'cve': 'CVE-2003-0858', 'key': "redhat.advisories.%.rhsa.id", 'val': "RHSA-2003:315"},
         'Saint':            {'cve': 'CVE-2006-6183', 'key': "saint.%.id",                  'val': "ftp_3cservertftp"},
         'VendorStatements': {'cve': 'CVE-1999-0524', 'key': "statements.%.contributor",    'val': "Joshua Bressers"},
         'VMWare':           {'cve': 'CVE-2015-5177', 'key': "vmware.%.id",                 'val': "VMSA-2015-0007"},
        }
_verbose = False


def testAll(cves, testdata, verbose):
  failed_tests = set()
  for name, data in testdata.items():
    if not test(cves, name, data['cve'], data['key'], data['val'], verbose):
      failed_tests.add(name)
  if not verbose:
    if len(failed_tests) != 0:
      print("[-] Some unit tests failed!")
      for failure in failed_tests: print("  -> %s"%failure)
    else: print("[+] All tests successful")

def test(cves, collection, cve, key, val, verbose):
  successful = False
  def check_level(_map, key, val):
    global successful
    if type(key) == str: key = key.split(".")
    for level, part in enumerate(key):
      if level == len(key)-1:
        if part == '%':
          for item in _map: 
            if item == val: successful = True
        else:
          if _map[part] == val: successful = True
      if part != "%": _map = _map[part]
      else:
        for item in _map:
          check_level(item, key[level+1:], val)
        break
    return successful

  try:
    if check_level(cves[cve], key, val):
      if verbose: print("[+] %s test succeeded!"%collection)
      return True
    else:
      if verbose: print("[-] %s test not succesful!"%collection)
  except Exception as e:
    if verbose:
      print("[-] %s test failed! %s"%(collection, e))
      traceback.print_exc()
  return False
