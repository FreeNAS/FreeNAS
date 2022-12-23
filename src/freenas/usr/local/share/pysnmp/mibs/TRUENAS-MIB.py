# PySNMP SMI module. Autogenerated from smidump -f python TRUENAS-MIB
# by libsmi2pysnmp-0.1.3 at Fri Dec 23 13:45:21 2022,
# Python version sys.version_info(major=3, minor=9, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( Bits, Counter32, Counter64, Gauge32, Integer32, Integer32, ModuleIdentity, MibIdentifier, NotificationType, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, enterprises, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Counter32", "Counter64", "Gauge32", "Integer32", "Integer32", "ModuleIdentity", "MibIdentifier", "NotificationType", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks", "enterprises")
( DisplayString, TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")

# Types

class AlertLevelType(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(1,2,3,4,5,6,7,)
    namedValues = NamedValues(("info", 1), ("notice", 2), ("warning", 3), ("error", 4), ("critical", 5), ("alert", 6), ("emergency", 7), )
    

# Objects

trueNas = ModuleIdentity((1, 3, 6, 1, 4, 1, 50536)).setRevisions(("2022-12-21 18:00",))
if mibBuilder.loadTexts: trueNas.setOrganization("www.ixsystems.com")
if mibBuilder.loadTexts: trueNas.setContactInfo("postal:   2490 Kruse Dr\nSan Jose, CA 95131\n\nemail:    support@iXsystems.com")
if mibBuilder.loadTexts: trueNas.setDescription("TrueNAS Specific MIBs")
zfs = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 1))
zpool = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 1, 1))
zpoolTable = MibTable((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1))
if mibBuilder.loadTexts: zpoolTable.setDescription("")
zpoolEntry = MibTableRow((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1)).setIndexNames((0, "TRUENAS-MIB", "zpoolIndex"))
if mibBuilder.loadTexts: zpoolEntry.setDescription("")
zpoolIndex = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 1), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 2147483647))).setMaxAccess("noaccess")
if mibBuilder.loadTexts: zpoolIndex.setDescription("")
zpoolName = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 2), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolName.setDescription("The name of the zpool")
zpoolHealth = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 3), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolHealth.setDescription("The health of the zpool")
zpoolReadOps = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 4), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolReadOps.setDescription("The number of read I/O operations sent to the pool or device,\nincluding metadata requests (averaged since system booted).")
zpoolWriteOps = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 5), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolWriteOps.setDescription("The number of write I/O operations sent to the pool or device\n(averaged since system booted).")
zpoolReadBytes = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 6), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolReadBytes.setDescription("The bandwidth of all read operations (including metadata),\nexpressed as units per second (averaged since system booted)")
zpoolWriteBytes = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 7), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolWriteBytes.setDescription("The bandwidth of all write operations, expressed as units per\nsecond (averaged since system booted).")
zpoolReadOps1sec = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 8), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolReadOps1sec.setDescription("The number of read I/O operations sent to the pool or device,\nincluding metadata requests (over 1 second interval).")
zpoolWriteOps1sec = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 9), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolWriteOps1sec.setDescription("The number of write I/O operations sent to the pool or device\n(over 1 second interval).")
zpoolReadBytes1sec = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 10), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolReadBytes1sec.setDescription("The bandwidth of all read operations (including metadata),\nexpressed as units per second (over 1 second interval)")
zpoolWriteBytes1sec = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 1, 1, 1, 11), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zpoolWriteBytes1sec.setDescription("The bandwidth of all write operations, expressed as units per\nsecond (over 1 second interval).")
zvol = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 1, 2))
zvolTable = MibTable((1, 3, 6, 1, 4, 1, 50536, 1, 2, 1))
if mibBuilder.loadTexts: zvolTable.setDescription("")
zvolEntry = MibTableRow((1, 3, 6, 1, 4, 1, 50536, 1, 2, 1, 1)).setIndexNames((0, "TRUENAS-MIB", "zvolIndex"))
if mibBuilder.loadTexts: zvolEntry.setDescription("")
zvolIndex = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 2, 1, 1, 1), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 2147483647))).setMaxAccess("noaccess")
if mibBuilder.loadTexts: zvolIndex.setDescription("")
zvolDescr = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 2, 1, 1, 2), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zvolDescr.setDescription("The name of the zvol")
zvolUsedBytes = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 2, 1, 1, 3), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zvolUsedBytes.setDescription("The zfs used property value")
zvolAvailableBytes = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 2, 1, 1, 4), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zvolAvailableBytes.setDescription("The zfs available property value")
zvolReferencedBytes = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 1, 2, 1, 1, 5), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zvolReferencedBytes.setDescription("The zfs referenced property value")
arc = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 1, 3))
zfsArcSize = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 1), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcSize.setDescription("")
zfsArcMeta = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 2), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcMeta.setDescription("")
zfsArcData = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 3), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcData.setDescription("")
zfsArcHits = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 4), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcHits.setDescription("")
zfsArcMisses = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 5), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcMisses.setDescription("")
zfsArcC = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 6), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcC.setDescription("")
zfsArcP = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 7), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcP.setDescription("")
zfsArcMissPercent = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 8), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcMissPercent.setDescription("Arc Miss Percentage.\n(Note: Floating precision sent across SNMP as a String")
zfsArcCacheHitRatio = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 9), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcCacheHitRatio.setDescription("Arc Cache Hit Ration Percentage.\n(Note: Floating precision sent across SNMP as a String")
zfsArcCacheMissRatio = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 3, 10), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsArcCacheMissRatio.setDescription("Arc Cache Miss Ration Percentage.\n(Note: Floating precision sent across SNMP as a String")
l2arc = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 1, 4))
zfsL2ArcHits = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 4, 1), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsL2ArcHits.setDescription("")
zfsL2ArcMisses = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 4, 2), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsL2ArcMisses.setDescription("")
zfsL2ArcRead = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 4, 3), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsL2ArcRead.setDescription("")
zfsL2ArcWrite = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 4, 4), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsL2ArcWrite.setDescription("")
zfsL2ArcSize = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 4, 5), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsL2ArcSize.setDescription("")
zil = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 1, 5))
zfsZilstatOps1sec = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 5, 1), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsZilstatOps1sec.setDescription("The ops column parsed from the command zilstat 1 1")
zfsZilstatOps5sec = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 5, 2), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsZilstatOps5sec.setDescription("The ops column parsed from the command zilstat 5 1")
zfsZilstatOps10sec = MibScalar((1, 3, 6, 1, 4, 1, 50536, 1, 5, 3), Counter64()).setMaxAccess("readonly")
if mibBuilder.loadTexts: zfsZilstatOps10sec.setDescription("The ops column parsed from the command zilstat 10 1")
notifications = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 2))
notificationPrefix = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 2, 1))
notificationObjects = MibIdentifier((1, 3, 6, 1, 4, 1, 50536, 2, 2))
alertId = MibScalar((1, 3, 6, 1, 4, 1, 50536, 2, 2, 1), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: alertId.setDescription("")
alertLevel = MibScalar((1, 3, 6, 1, 4, 1, 50536, 2, 2, 2), AlertLevelType()).setMaxAccess("readonly")
if mibBuilder.loadTexts: alertLevel.setDescription("")
alertMessage = MibScalar((1, 3, 6, 1, 4, 1, 50536, 2, 2, 3), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: alertMessage.setDescription("")
hddTempTable = MibTable((1, 3, 6, 1, 4, 1, 50536, 3))
if mibBuilder.loadTexts: hddTempTable.setDescription("Table of HDDs and their temperatures.")
hddTempEntry = MibTableRow((1, 3, 6, 1, 4, 1, 50536, 3, 1)).setIndexNames((0, "TRUENAS-MIB", "hddTempIndex"))
if mibBuilder.loadTexts: hddTempEntry.setDescription("An entry containing a HDD and its temperature.")
hddTempIndex = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 3, 1, 1), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0, 65535))).setMaxAccess("readonly")
if mibBuilder.loadTexts: hddTempIndex.setDescription("Reference index for each observed HDD.")
hddTempDevice = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 3, 1, 2), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: hddTempDevice.setDescription("The name of the HDD we are reading temperature from.")
hddTempValue = MibTableColumn((1, 3, 6, 1, 4, 1, 50536, 3, 1, 3), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: hddTempValue.setDescription("The temperature of this HDD in mC.")

# Augmentions

# Notifications

alert = NotificationType((1, 3, 6, 1, 4, 1, 50536, 2, 1, 1)).setObjects(*(("TRUENAS-MIB", "alertId"), ("TRUENAS-MIB", "alertLevel"), ("TRUENAS-MIB", "alertMessage"), ) )
if mibBuilder.loadTexts: alert.setDescription("An alert raised")
alertCancellation = NotificationType((1, 3, 6, 1, 4, 1, 50536, 2, 1, 2)).setObjects(*(("TRUENAS-MIB", "alertId"), ) )
if mibBuilder.loadTexts: alertCancellation.setDescription("An alert cancelled")

# Exports

# Module identity
mibBuilder.exportSymbols("TRUENAS-MIB", PYSNMP_MODULE_ID=trueNas)

# Types
mibBuilder.exportSymbols("TRUENAS-MIB", AlertLevelType=AlertLevelType)

# Objects
mibBuilder.exportSymbols("TRUENAS-MIB", trueNas=trueNas, zfs=zfs, zpool=zpool, zpoolTable=zpoolTable, zpoolEntry=zpoolEntry, zpoolIndex=zpoolIndex, zpoolName=zpoolName, zpoolHealth=zpoolHealth, zpoolReadOps=zpoolReadOps, zpoolWriteOps=zpoolWriteOps, zpoolReadBytes=zpoolReadBytes, zpoolWriteBytes=zpoolWriteBytes, zpoolReadOps1sec=zpoolReadOps1sec, zpoolWriteOps1sec=zpoolWriteOps1sec, zpoolReadBytes1sec=zpoolReadBytes1sec, zpoolWriteBytes1sec=zpoolWriteBytes1sec, zvol=zvol, zvolTable=zvolTable, zvolEntry=zvolEntry, zvolIndex=zvolIndex, zvolDescr=zvolDescr, zvolUsedBytes=zvolUsedBytes, zvolAvailableBytes=zvolAvailableBytes, zvolReferencedBytes=zvolReferencedBytes, arc=arc, zfsArcSize=zfsArcSize, zfsArcMeta=zfsArcMeta, zfsArcData=zfsArcData, zfsArcHits=zfsArcHits, zfsArcMisses=zfsArcMisses, zfsArcC=zfsArcC, zfsArcP=zfsArcP, zfsArcMissPercent=zfsArcMissPercent, zfsArcCacheHitRatio=zfsArcCacheHitRatio, zfsArcCacheMissRatio=zfsArcCacheMissRatio, l2arc=l2arc, zfsL2ArcHits=zfsL2ArcHits, zfsL2ArcMisses=zfsL2ArcMisses, zfsL2ArcRead=zfsL2ArcRead, zfsL2ArcWrite=zfsL2ArcWrite, zfsL2ArcSize=zfsL2ArcSize, zil=zil, zfsZilstatOps1sec=zfsZilstatOps1sec, zfsZilstatOps5sec=zfsZilstatOps5sec, zfsZilstatOps10sec=zfsZilstatOps10sec, notifications=notifications, notificationPrefix=notificationPrefix, notificationObjects=notificationObjects, alertId=alertId, alertLevel=alertLevel, alertMessage=alertMessage, hddTempTable=hddTempTable, hddTempEntry=hddTempEntry, hddTempIndex=hddTempIndex, hddTempDevice=hddTempDevice, hddTempValue=hddTempValue)

# Notifications
mibBuilder.exportSymbols("TRUENAS-MIB", alert=alert, alertCancellation=alertCancellation)

