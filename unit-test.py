if __name__ == "__main__":
  import test

  import json
  cves = json.loads(open("VIA4CVE-feed.json").read())
  test.testAll(cves, test.tests, test._verbose)
