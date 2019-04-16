from urllib.request import urlopen as urlReq, urlretrieve as urlDownload, Request
from pathlib import Path
import hashlib, traceback
import sys
import re
import json
import shutil
import os
import yara

ver = ""
badHashFiles = []


def banner():
    print("""
                                     _                    
                   /\               | |                   
 __      ___ __   /  \   _ __   __ _| |_   _ _______ _ __ 
 \ \ /\ / / '_ \ / /\ \ | '_ \ / _` | | | | |_  / _ \ '__|
  \ V  V /| |_) / ____ \| | | | (_| | | |_| |/ /  __/ |   
   \_/\_/ | .__/_/    \_\_| |_|\__,_|_|\__, /___\___|_|   
          | |                           __/ |             
          |_|                          |___/   beta version""")


def Target_Files(pwd):
    allFiles = list(Path(pwd).rglob("*"))
    return(allFiles)


def Answer_Ver():
    global ver
    ver = input("\n\nWhat is the wordpress version of target site?: ")


def Yara_Checker():
    if Path("./yaraRules").exists:
        return True
    else:
        return False


def Core_Analysis(paths):
    global badHashFiles
    print("\n_______________________CORE FILES HASHES ANALYSIS_______________________\n")
    print("\n")
    fullBadFiles = [None]
    apiHashes = Pull_Json(ver)
    for pthFile in paths:
        if str(pthFile) in apiHashes["checksums"][ver]:
            checksum = Md5_Sum(pthFile)
            badFile = str(Compare_Hash(apiHashes, checksum, pthFile, ver))
            if badFile != "None":
                fullBadFiles.append(badFile)
    print("________________________________________________________________________\n")
    if fullBadFiles == [None]:
        print("All analyzed files keep the correct hashes\n")
    badHashFiles = fullBadFiles


def Compare_Hash(apiHashes, chkSum, pthFile, ver):
    if chkSum != apiHashes["checksums"][ver][str(pthFile)]:
        print("Hash for \"{}\" is \"{}\" and should be \"{}\"".format(
            pthFile, chkSum, apiHashes["checksums"][ver][str(pthFile)]))
        return(pthFile)


def WP_CoreFiles_Replace():
    recovery = input(
        "Do you want download and replace the core files with invalid hashes?: (y/n) ").lower()
    if recovery == "y":
        print("\nBegin the replacing actions:")
        print("\n\tDownload Wordpress Core:\n\t")
        NewCoreFolder = Download_File(ver)
        for targetFile in badHashFiles:
            src = NewCoreFolder + "/wordpress/" + str(targetFile)
            dst = targetFile
            if targetFile == None:
                exit
            else:
                shutil.copyfile(src, dst)
        # Private code block for wp-config.php
        choice = input(
            "Do you want create a new wp-config.php?: (y/n) ").lower()
        if choice == "n":
            exit
        elif choice == "y":
            os.rename("wp-config.php", "wp-config.php.OLD")
            copiedData = Build_WP_Config(NewCoreFolder)
            # print(copiedData)
    elif recovery == "n":
        Handler()


def Build_WP_Config(NewCoreFolder):
    with open("wp-config.php", "w", encoding="ISO-8859-1") as configFile:
        with open(NewCoreFolder + "/wordpress/wp-config-sample.php", "r", encoding="ISO-8859-1") as sampleFile:
            lines = sampleFile.readlines()
            parsedData = [configFile.write(Compare_Strings(line)) if Compare_Strings(
                line) else configFile.write(line) for line in lines]
            return(parsedData)


def Compare_Strings(line):
    listPatterns = [r"define\('DB_NAME', '", r"define\('DB_USER', '",
                    r"define\('DB_PASSWORD', '", r"define\('DB_HOST', '"]
    match = [pattern for pattern in listPatterns if line.replace(
        " ", "").startswith(pattern.replace(" ", "").replace("\\", ""))]
    if match:
        # "match" is a list (list is what return a comprehension list) and Parse_WP_Config receive a str because of this: "".join(match)
        return(Parse_WP_Config("".join(match)))


def Parse_WP_Config(ptr):
    pattern = re.compile(ptr)
    with open("wp-config.php.OLD", "r", encoding="ISO-8859-1") as configFile:
        return("".join([line for line in configFile.readlines() if pattern.match(line)]))


def Find_Suspect_Code(paths):
    words_payloads = ("0x4c2c", "FilesMan", "eval(", "explode(",
                      "preg_replace(", "\\x", "c2q5g", "\\u")
    ext = (".gif", ".png", ".jpeg", ".jpg", ".zip")
    for pthFile in paths:
        occurrences = []
        if pthFile.is_dir() or str(pthFile.suffix) in ext:
            continue
        else:
            with open(str(pthFile), "r", encoding="ISO-8859-1") as target:
                for line in target:
                    for badWord in words_payloads:
                        if badWord in line and badWord not in occurrences:
                            occurrences.append(badWord)
                        else:
                            continue
        if not occurrences:
            continue
        print("\nFile \"{}\" with dangerous function, expression or conding: \"{}\"".format(
            pthFile, occurrences))
    Handler()


def Yara_Malware_Analysis():
    # A recursive function needed here; some rules included in index rules file are broken so we need caught this 
    # exception, parse the message for match the malformed rule name and remove it, first from index file and the file itself later. 
    try:
        indexRules = yara.compile(filepath="./yaraRules/rules-master/malware_index.yar")
    except yara.SyntaxError:
        #Extract malformed rule filename from "sys.exc_info(): return information about the exception that is being handled" 
        excFile = str(sys.exc_info()[1]).split("(")[0]
        print("\nError loading: " + "\x1b[1;31m" + Path(excFile).name + "\x1b[0;m" + " rule, it will be removed")
        modContent = []
        with open("./yaraRules/rules-master/malware_index.yar", "r", encoding="ISO-8859-1") as indexFile:
            # List comprehensions are shorter TODO: Change all modification files functions on this way
            modContent += [line for line in indexFile.readlines() if Path(excFile).name not in line]
        with open("./yaraRules/rules-master/malware_index.yar", "w", encoding="ISO-8859-1") as indexFile:
            indexFile.write("\n".join(modContent))
        return Yara_Malware_Analysis()
        
    excludeSuffix = [".yar", ".yara"]
    allFiles = Target_Files(".")
    print("\n\n_______________________YARA MALWARE ANALYSIS_______________________\n")
    for pthFile in allFiles:
        if pthFile.is_dir() or str(pthFile.suffix) in excludeSuffix:
            continue
        malwareMatch = indexRules.match(data=open(str(pthFile), "rb").read())
        if not malwareMatch:
            continue
        else:
            print(malwareMatch, "--> RULE MATCHED in file --> {}".format(str(pthFile)))
    print("____________________________________________________________________\n")
    Handler()


def Yara_Webshells_Analysis():
    indexRules = yara.compile(
        filepath="./yaraRules/rules-master/Webshells_index.yar")
    allFiles = Target_Files(".")
    excludeDir = "yaraRules/rules-master/Webshells"
    print("\n_______________________YARA WEBSHELL ANALYSIS_______________________\n")
    for pthFile in allFiles:
        if pthFile.is_dir() or str(pthFile.parent) == excludeDir:
            continue
        webShellMatch = indexRules.match(data=open(str(pthFile), "rb").read())
        if not webShellMatch:
            continue
        else:
            print(webShellMatch, "--> RULE MATCHED in file --> {}".format(str(pthFile)))
    print("____________________________________________________________________\n")

    Handler()


def Yara_Personal_Rules():
    if not Path("./personalRule.yar").is_file():
        print(
            "\x1b[1;31m" + "\n\nThe personal rule file [./personalRule.yar] doesn't exists" + "\x1b[0;m")
        Handler()
    rule = yara.compile(filepath="./personalRule.yar")
    allFiles = Target_Files(".")
    print("\n\n_______________________YARA PERSONAL RULE ANALYSIS_______________________\n")
    for pthFile in allFiles:
        if pthFile.is_dir():
            continue
        match = rule.match(data=open(str(pthFile), "rb").read())
        if not match:
            continue
        else:
            print(match, "--> RULE MATCHED in file --> {}".format(str(pthFile)))
    print("_________________________________________________________________________\n")

    Handler()


def Yara_Rules_Adaptation():
    yaraPath = str(Path.cwd())
    indexPath = str(yaraPath) + "/yaraRules/rules-master/malware_index.yar"
    toReplace = "./"
    modPath = str(yaraPath) + "/yaraRules/rules-master/"
    # This rules require Cuckoo sandbox installed and return an error
    # that crash wpAnalyzer workflow.
    cuckooRules = ["AZORULT"]
    modContent = ""
    with open(indexPath, "r") as indexFile:
        for line in indexFile.readlines():
            for badRule in cuckooRules:
                if badRule in line:
                    continue
                modContent += line.replace(toReplace, modPath)

    with open(indexPath, "w") as indexFile:
        indexFile.write(modContent)


def Pull_Json(ver):
    base = "https://api.wordpress.org/core/checksums/1.0/?version="
    url = base + ver
    siteResponse = urlReq(url).read()
    jsonHashes = json.loads(siteResponse.decode("utf-8"))
    return(jsonHashes)


def Md5_Sum(pathFile):
    checkerSum = hashlib.md5()
    with open(str(pathFile), "rb") as target:
        buf = target.read()
        checkerSum.update(buf)
    checksumFile = (checkerSum.hexdigest())
    return(checksumFile)


def Download_Progress(chunk, chunkSize, totalSize):
    downloadedSize = int(chunk * chunkSize)
    progress = int((downloadedSize / totalSize)*100)
    print("\t\tDownload progress: {} %".format(str(progress)))


def Download_File(ver):
    if ver == "yara":
        try:
            rcvFolder = Path("./yaraRules")
            url = "https://github.com/Yara-Rules/rules/archive/master.zip"
            urlDownload(url, "rules-master.zip",
                        reporthook=Download_Progress)
            print("\n\tDownload finished")
            if not rcvFolder.is_dir:
                try:
                    os.makedirs(str(rcvFolder))
                except OSError:
                    print("The target folder: {} cannot be created".format(
                        str(rcvFolder)))
            else:
                shutil.unpack_archive("rules-master.zip", str(rcvFolder))
        except OSError:
            print("Something went wrong, maybe the permission over this folder.")
        return(str(rcvFolder.absolute()), "yaraOK")

    else:
        try:
            rcvFolder = Path("./wp_" + ver)
            url = "https://wordpress.org/wordpress-" + ver + ".tar.gz"
            urlDownload(url, "wp_" + ver + ".tar.gz",
                        reporthook=Download_Progress)
            print("\n\tDownload finished")
            if not rcvFolder.is_dir:
                try:
                    os.makedirs(str(rcvFolder))
                except OSError:
                    print("The target folder: {} cannot be created".format(
                        str(rcvFolder)))
            else:
                shutil.unpack_archive("wp_" + ver + ".tar.gz", str(rcvFolder))
        except OSError:
            print("Something went wrong, maybe the Wordpress version inserted.")
        return(str(rcvFolder.absolute()))


def Garbage_Collector(ver):
    shutil.rmtree("./wp_" + ver)
    Path.unlink(Path("./wp_" + ver + ".tar.gz"))
    Handler()


def Wpvuldb_Api(data):
    # Will match in case data is a Wordpress version
    regexVer = re.compile(r"^(\d{1,3}\.\d{0,3}\.{0,1}\d{0,3})")

    if regexVer.match(data):
        # The query is about Wordpress vulnerabilities
        base = "https://wpvulndb.com/api/v3/wordpresses/"
        url = base + data.replace(".", "")
    else:
        # The query is about Plugins vulnerabilities (a regex to match could be made but.. if "data" isn't
        # a WP version is a plugin name(slug))
        base = "https://wpvulndb.com/api/v3/plugins/"
        url = base + data

    token = ""
    authHeader = {"Authorization": "Token token=" + token}
    apiReq = Request(url, headers=authHeader)
    siteResponse = urlReq(apiReq).read()
    jsonResponse = json.loads(siteResponse.decode("ISO-8859-1"))
    listVuln = jsonResponse[data]["vulnerabilities"]

    for vuln in listVuln:
        vulName = vuln.get("title")
        vulType = vuln.get("vuln_type")
        vulDate = vuln.get("created_at")
        vulRef = vuln["references"].get("url")
        vulCVE = vuln["references"].get("cve")

        print("\n\n\tVulnerability name: " + vulName + "\n\tType: " + vulType + "\n\tDate: \
" + vulDate + "\n\tReferences: " + str(vulRef) + "\n\tCVE: " + str(vulCVE))


def Plugins_Enum():
    try:
        pwd = "./wp-content/plugins"
        plgFolders = [subDir for subDir in Path(
            pwd).iterdir() if subDir.is_dir()]
        rdmFile = "/README.txt"

        for slug in plgFolders:
            base = "https://api.wordpress.org/plugins/info/1.1/?action=query_plugins&request[search]="
            url = base + slug.name
            siteResponse = urlReq(url).read()
            jsonResponse = json.loads(siteResponse.decode("ISO-8859-1"))

            firstMatch = jsonResponse["plugins"][0]

            plgName = firstMatch.get("name")
            plgVersion = firstMatch.get("version")
            plgAuthor = firstMatch.get("author_profile")
            plgSite = firstMatch.get("homepage")
            plgWPReq = firstMatch.get("requires")

            if Path(str(slug) + rdmFile).is_file():
                instVersion = verParser(rdmFile, slug)
            elif Path(str(slug) + rdmFile.lower()).is_file():
                instVersion = verParser(rdmFile.lower(), slug)

            # Show info from Wordpress Api for each plugin parsed
            print("\n\nPlugin name: " + plgName + "\x1b[1;31m" + "\nLatest version: " + plgVersion + "\nInstalled \
version:" + instVersion + "\x1b[0;m" + "\nAuthor: " + plgAuthor + "\nSite: " + plgSite + "\nWordpress \
version required: " + plgWPReq)

            # Show a list of vulnerabilities store in wpvulndb for each plugin parsed
            Wpvuldb_Api(slug.name)
    except:
        print("The directory \"wp-content\" doesn't exist, therefore plugins cannot be enumerated")

    Handler()


def verParser(fileName, slug):
    regEx = re.compile(r"(?!(?:#\n))(#|=)(\s{1})(\d+\.\d+\.\d+|\d+\.\d+|\d+)")

    try:
        with open(str(slug) + fileName, "r", encoding="ISO-8859-1") as rdmFile:
            fullText = rdmFile.read()
            plgVersion = regEx.search(fullText)
            if plgVersion:
                plgVersion = plgVersion.group(3)
                return(plgVersion)
    except EnvironmentError:
        print("Plugin version cannot be determined.")


def Handler(*args):

    print("\n\n1. Analyze Wordpress Core files hashes.\n2. Replace Wordpress \
Core files from trust source.\n3. Find suspect variables and functions.\n4\
. Download YARA Rules (latest).\n5. Malware analysis using YARA.\n6. WebShells \
analysis using YARA.\n7. Load personal rule file and launch YARA.\n8. Show WORDPRESS \
vulnerabilities affecting to installed Wordpress version. Source: WPVULNDB Database \
(WPScan/Wordpressa).\n9. Show PLUGINS vulnerabilities. \
Source: WPVULNDB Database (WPScan/Wordpressa).\n10. Exit\n\n")

    choice = input("Select an option: ")

    while True:
        if choice == "1":
            result = Target_Files(".")
            Core_Analysis(result)
            Handler()
        elif choice == "2":
            WP_CoreFiles_Replace()
            Garbage_Collector(ver)
        elif choice == "3":
            fullListFiles = Target_Files(".")
            Find_Suspect_Code(fullListFiles)
        elif choice == "4":
            yaraFolder = Download_File("yara")
            print("\nYARA installation folder is: {}".format(yaraFolder[0]))
            Handler()
        elif choice == "5":
            if Yara_Checker():
                Yara_Rules_Adaptation()
                Yara_Malware_Analysis()
            else:
                print("You must download YARA first")
                Handler()
        elif choice == "6":
            if Yara_Checker():
                Yara_Webshells_Analysis()
            else:
                print("You must download YARA first")
                Handler()
        elif choice == "7":
            if Yara_Checker():
                Yara_Personal_Rules()
            else:
                print("You must download YARA first")
                Handler()
        elif choice == "8":
            Wpvuldb_Api(ver)
            Handler()
        elif choice == "9":
            Plugins_Enum()
            Handler()
        elif choice == "10":
            print("\nBye bye!!\n")
            exit(0)
        break


def main():
    banner()
    Answer_Ver()
    Handler()


if __name__ == "__main__":
    main()

