class Source():
  def __init__(self):
    self.name = "" # to override
    self.cves = {} # empty cve set
    raise(Exception("Please override this function and give it a name!"))

  def getCVEs(self):
    return self.cves.keys()

  def getRefs(self, cve):
    return self.cves.get(cve, {})

  def updateRefs(self, cveID, cveData):
    return self.cves
