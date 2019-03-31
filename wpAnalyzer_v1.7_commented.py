from urllib.request import urlopen as urlReq
from urllib.request import urlretrieve as urlDownload
from pathlib import Path
import hashlib
import sys
import re
import json
import shutil
import os
import yara


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

# Generates a list with all the files, folder and subf from the current directory. 
def Target_Files(pwd):
    allFiles = list(Path(pwd).rglob("*"))
    return(allFiles)

# Check for Yara rules in local system
def Yara_Checker():
    if Path("./yaraRules").exists:
        return True
    else:
        return False

# Generates the md5 hash of each local file about we have the official hash and compare it.
def Core_Analysis(paths):
    print("\n_______________________CORE FILES HASHES ANALYSIS_______________________\n")
    ver = input("What is the wordpress version of target site?: ")
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
        print("All analyzed files have the correct hashes\n")
    return(fullBadFiles, ver)

# Compare local file hash with wordpress api hash for that file
def Compare_Hash(apiHashes, chkSum, pthFile, ver):
    if chkSum != apiHashes["checksums"][ver][str(pthFile)]:
        print("Hash for \"{}\" is \"{}\" and should be \"{}\"".format(
            pthFile, chkSum, apiHashes["checksums"][ver][str(pthFile)]))
        return(pthFile)

# Download a new WP matching the local version and replace all bad hashes files
def WP_CoreFiles_Replace(listBadFiles, ver):
    recovery = input(
        "Do you want download and replace the core files with invalid hashes?: (y/n)").lower()
    if recovery == "y":
        print("\nBegin the replacing actions:")
        print("\n\tDownload Wordpress Core:\n\t")
        NewCoreFolder = Download_File(ver)
        for targetFile in listBadFiles:
            src = NewCoreFolder + "/wordpress/" + str(targetFile)
            dst = targetFile
            if targetFile == None:
                exit
            else:
                shutil.copyfile(src, dst)
    elif recovery == "n":
        Handler()

# Basic hardcode suspicious strings analysis
def Find_Suspect_Code(paths):
    words_payloads = ("0x4c2c", "pwkcz", "eval(", "explode(",
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

# Manipulation of malware_index.yar for match with local paths, remove Cuckoo Sandbox rules, 
# load all malware rules included in index and analysis of the file list.
def Yara_Malware_Analysis():
    Yara_Rules_Adaptation()
    indexRules = yara.compile(filepath="./yaraRules/rules-master/malware_index.yar")
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

# Yara webshells rules load and analysis
def Yara_Webshells_Analysis():
    indexRules = yara.compile(filepath="./yaraRules/rules-master/Webshells_index.yar")
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

# Yara load personal rule (current folder and name: lepetitpol.yar)
def Yara_Personal_Rules():
    rule = yara.compile(filepath="./lepetitpol.yar")
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

# Manipulation of downloaded index file: path change and rule remove.
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

# Retrieve of the official hashes for every core and plugin(not all) file for a given WP version
def Pull_Json(ver):
    base = "https://api.wordpress.org/core/checksums/1.0/?version="
    url = base + ver
    siteResponse = urlReq(url).read()
    jsonHashes = json.loads(siteResponse.decode("utf-8"))
    return(jsonHashes)

# Generate the md5 hash of a local file
def Md5_Sum(pathFile):
    checkerSum = hashlib.md5()
    with open(str(pathFile), "rb") as target:
        buf = target.read()
        checkerSum.update(buf)
    checksumFile = (checkerSum.hexdigest())
    return(checksumFile)

# Simple download information
def Download_Progress(chunk, chunkSize, totalSize):
    downloadedSize = int(chunk * chunkSize)
    progress = int((downloadedSize / totalSize)*100)
    print("\t\tDownload progress: {} %".format(str(progress)))

# Download YARA or WP
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

# Once the files with bad hash have been replaced, the downloaded files are deleted
def Garbage_Collector(ver):
    shutil.rmtree("./wp_" + ver)
    Path.unlink(Path("./wp_" + ver + ".tar.gz"))
    Handler()

# Menu
def Handler(*args):

    print("\n\n1. Analyze Wordpress Core files hashes.\n2. Replace Wordpress \
Core files from trust source.\n3. Find suspect variables and functions.\n4\
. Download YARA Rules (latest).\n5. Malware analysis using YARA.\n6. WebShells \
analysis using YARA.\n7. Load personal rule file and launch YARA.\n8. Exit\n\n")

    choice = input("Select an options: ")

    while True:
        if choice == "1":
            result = Target_Files(".")
            badHashFiles, ver = Core_Analysis(result)
            Handler(badHashFiles, ver)
        elif choice == "2":
            if not args:
                print("You must analyze your local installations first")
                Handler()
            else:
                WP_CoreFiles_Replace(args[0], args[1])
                Garbage_Collector(args[1])
        elif choice == "3":
            fullListFiles = Target_Files(".")
            Find_Suspect_Code(fullListFiles)
        elif choice == "4":
            yaraFolder = Download_File("yara")
            print("\nYARA installation folder is: {}".format(yaraFolder[0]))
            Handler()
        elif choice == "5":
            if  Yara_Checker():
                Yara_Malware_Analysis()
            else:
                print("You must download YARA first")
                Handler()
        elif choice == "6":
            if  Yara_Checker():
                Yara_Webshells_Analysis()
            else:
                print("You must download YARA first")
                Handler()
        elif choice == "7":
            if  Yara_Checker():
                Yara_Personal_Rules()
            else:
                print("You must download YARA first")
                Handler()
        elif choice == "8":
            print("\nBye bye!!\n")
            exit(0)
        break


def main():
    banner()
    Handler()


if __name__ == "__main__":
    main()