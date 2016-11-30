import json

from lib.PluginManager import PluginManager

pm = PluginManager()
pm.loadPlugins()

cves = {}
for _id in pm.getAllCVEIDs():
  cves[_id] = pm.getCVERefs(_id)

for _id in cves.keys():
  pm.updateRefs(_id, cves[_id])

for _id in cves.keys():
  pm.cleanUp(_id, cves[_id])

open("VIA4CVE-feed.json", "w").write(json.dumps(cves))
