import json
import sys

def createDict():
    featuresDict = dict()
    featuresDict["Dead store"] = 0
    featuresDict["Uninitialized memory"] = 0
    featuresDict["Case termination"] = 0
    featuresDict["Check stdlibfunc return"] = 0
    featuresDict["Cfg innnvoid function"] = 0
    featuresDict["Xfree"] = 0
    featuresDict["Double free"] = 0
    featuresDict["Dangling Switch"] = 0
    return featuresDict

def convertFeaturesToTuple(features):
    sortedFeatures = sorted(features)
    return tuple(sortedFeatures)

def createSet(jsonDictList):

    result = set()
    for x in jsonDictList:
        result.add((x['filename'],x['line'],convertFeaturesToTuple(x['automatic_features']),x['type']))
    return result

def main():
    with open(sys.argv[1],'r') as fileDict:
        featuresArray = json.load(fileDict)
        featuresSet = createSet(featuresArray)
        featuresDict = createDict()
        numVariability = 0
        featuresSet = list(featuresSet)
        for x in featuresSet:
            if "True" not in x[2]:
                numVariability += 1
            featuresDict[x[3].strip()] += 1
        print("The number of Dead Store warnings is {} or {}% of all warnings".format(featuresDict["Dead store"],round(featuresDict["Dead store"]/len(featuresSet)*100,2)))
        print("The number of Dangling Switch warnings is {} or {}% of all warnings".format(featuresDict["Dangling Switch"],round(featuresDict["Dangling Switch"]/len(featuresSet)*100,2)))
        print("The number of Uninitialized Memory warnings is {} or {}% of all warnings".format(featuresDict["Uninitialized memory"],round(featuresDict["Uninitialized memory"]/len(featuresSet)*100,2)))
        print("The number of Case Termination warnings is {} or {}% of all warnings".format(featuresDict["Case termination"],round(featuresDict["Case termination"]/len(featuresSet)*100,2)))
        print("The number of Check Stdlibfunc Return warnings is {} or {}% of all warnings".format(featuresDict["Check stdlibfunc return"],round(featuresDict["Check stdlibfunc return"]/len(featuresSet)*100,2)))
        print("The number of Cfg Innnvoid Function warnings is {} or {}% of all warnings".format(featuresDict["Cfg innnvoid function"],round(featuresDict["Cfg innnvoid function"]/len(featuresSet)*100,2)))
        print("The number of Xfree warnings is {} or {}% of all warnings".format(featuresDict["Xfree"],round(featuresDict["Xfree"]/len(featuresSet)*100,2)))
        print("The number of Double Free warnings is {} or {}% of all warnings".format(featuresDict["Double free"],round(featuresDict["Double free"]/len(featuresSet)*100,2)))
        print("The number of Variability warnings is {} or {}% of all warnings".format(numVariability,round(numVariability/len(featuresSet)*100,2)))
        print("The number of Total warnings is {} or {}% of all warnings".format(len(featuresSet),round(len(featuresSet)/len(featuresSet)*100,2)))

main()