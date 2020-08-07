Author: In Ming Loh (inming.loh@countercept.com - @tantaryu) <br />
Company: Countercept (@countercept) <br />
Website: https://www.countercept.com <br />

## Introduction
A script that helps researcher to unpack and decompile executable written in python. However, right now this only supports executable created with py2exe and pyinstaller.

This script glues together several tools available to the community. Hopefully, this can help people in their daily job. Several YARA rules are available to determine if the executable is written in python (This script also confirms if the executable is created with either py2exe or pyinstaller).

## Requirements & Install


### Docker

Build the image with: `docker build -t python_exe_unpack .`
Run the image with: `docker run --rm -it -v $(pwd):/data python_exe_unpack`

Your current dir will be exposed as `/data` in the container...


### Manual Install 
- Python 2.7 or later. 
- Install all the dependency needed:<br/>
    `pip2 install --user -r requirements.txt`<br/>
        or if you fancy to have your dependency installed with root permission<br/>
    `sudo pip2 install -r requirements.txt`


## Getting Started
- python python_exe_unpack.py -i [malware.exe]
    * pyinstaller
        * A folder will be created with the original filename concatenated with "_extracted". For example: "malware.exe_extracted".
        * The main python file that contains the logic will usually be the file without any extension (In the folder that concatenated with "_extracted"). In the following example, "hello" is the one that contains the main python logic:<br/>
        `-rw-rw-r-- 1 testuser testuser  70K Nov 14 13:08 bz2.pyd`<br/>
        `-rw-rw-r-- 1 testuser testuser 993K Nov 14 13:08 _hashlib.pyd`<br/>
        `-rw-rw-r-- 1 testuser testuser  111 Nov 14 13:08 hello`<br/>
        `-rw-rw-r-- 1 testuser testuser 1009 Nov 14 13:08 hello.exe.manifest`<br/>
        `-rw-rw-r-- 1 testuser testuser 1.1K Nov 14 13:08 Microsoft.VC90.CRT.manifest`<br/>
        `-rw-rw-r-- 1 testuser testuser 220K Nov 14 13:08 msvcm90.dll`<br/>
        `-rw-rw-r-- 1 testuser testuser 557K Nov 14 13:08 msvcp90.dll`<br/>
        `-rw-rw-r-- 1 testuser testuser 638K Nov 14 13:08 msvcr90.dll`<br/>
        `-rw-rw-r-- 1 testuser testuser 628K Nov 14 13:08 out00-PYZ.pyz`<br/>
        `drwxrwxr-x 2 testuser testuser  12K Nov 14 13:08 out00-PYZ.pyz_extracted`<br/>
        `-rw-rw-r-- 1 testuser testuser 5.2K Nov 14 13:08 pyiboot01_bootstrap`<br/>
        `-rw-rw-r-- 1 testuser testuser 2.5K Nov 14 13:08 pyimod01_os_path`<br/>
        `-rw-rw-r-- 1 testuser testuser  12K Nov 14 13:08 pyimod02_archive`<br/>
        `-rw-rw-r-- 1 testuser testuser  22K Nov 14 13:08 pyimod03_importers`<br/>
        `-rw-rw-r-- 1 testuser testuser    0 Nov 14 13:08 pyi-windows-manifest-filename hello.exe.manifest`<br/>
        `-rw-rw-r-- 1 testuser testuser 2.6M Nov 14 13:08 python27.dll`<br/>
        `-rw-rw-r-- 1 testuser testuser  10K Nov 14 13:08 select.pyd`<br/>
        `-rw-rw-r-- 1 testuser testuser  234 Nov 14 13:08 struct`<br/>
        `-rw-rw-r-- 1 testuser testuser 671K Nov 14 13:08 unicodedata.pyd`<br/>
        * pyinstaller has an option that can encrypt python bytecode. This script will try to decrypt it and decompile the decrypted code.
    * py2exe
        * The result of unpacking and decompiling will be located in folder "unpacked" or the location you specify.
        * If error like this shows "Error in unpacking the exe. Probably due to version incompability (exe created using python 2 and run this script with python 3)", try setting your python to a different version than the one you are using. Eg: "alias python=python2" or "alias python=python3"

- python python_exe_unpack.py -p [pyc file]
    * In the above example, sometimes the python file that contains the main logic will not be in the format that uncompyle6 accept (Missing python magic numbers). The above command will prepend magic numbers and decompile it (If magic number is already preprended it will not add it and just proceed with decompiling).

## Credits
- Extreme Coders for their pyinstxtractor.py script to help unpack pyinstaller executable.
- Extreme Coders for their instruction on how to decrypt encrypted python byte code: https://0xec.blogspot.sg/2017/02/extracting-encrypted-pyinstaller.html
- unpy2exe 
- uncompyle6 
