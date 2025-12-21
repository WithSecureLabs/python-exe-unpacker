#!/usr/bin/python

"""

Version 1.8.1 (December 20, 2025) / 版本1.8.1 2025年12月20日
-------------------------------------------------
- 修复在3.x.x版本时无法运行的问题 / Fix the issue that prevented running in version 3.x.x

"""

"""
Author: Liu Yu chen / 刘宇晨
Email: liuyuchen032901@outlook.com（qq.com)

Liu Yuchen made changes to version 1.8 on December 20, 2025. / 刘宇辰于2025年12月20日对1.8版本进行了修改。
Liu Yu chen am not the maintainer of this project / 刘宇晨不是这个项目的维护者

The content of the statement is translated using machine translation / 声明内容使用机器翻译

CHANGELOG / 修改日志
================================================
- 修复在3.x.x版本时无法运行的问题 / Fix the issue that prevented running in version 3.x.x
- 添加zh-cn语言支持 / Add zh-CN language support

"""


import os
import struct
import marshal
import zlib
import sys
import types
from uuid import uuid4 as uniquename

# 导入 importlib 替代已弃用的 imp 模块
import importlib.util
import importlib.machinery

# 获取 Python 魔数字节，替代 imp.get_magic()
def get_python_magic():
    """获取当前 Python 解释器的魔数字节 / Get the magic number of current Python interpreter"""
    try:
        # Python 3.4+
        return importlib.util.MAGIC_NUMBER
    except AttributeError:
        # Python 2.x 兼容性 / Python 2.x compatibility
        import imp
        return imp.get_magic()


class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path


    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            print('[*] Error: Could not open {0} / 错误：无法打开 {0}'.format(self.filePath))
            return False
        return True


    def close(self):
        try:
            self.fPtr.close()
        except:
            pass


    def checkFile(self):
        print('[*] Processing {0} / 处理中 {0}'.format(self.filePath))
        # Check if it is a 2.0 archive
        self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            self.pyinstVer = 20     # pyinstaller 2.0
            print('[*] Pyinstaller version: 2.0 / PyInstaller 版本: 2.0')
            return True

        # Check for pyinstaller 2.1+ before bailing out
        self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            print('[*] Pyinstaller version: 2.1+ / PyInstaller 版本: 2.1+')
            self.pyinstVer = 21     # pyinstaller 2.1+
            return True

        print('[*] Error : Unsupported pyinstaller version or not a pyinstaller archive / 错误：不支持的 PyInstaller 版本或不是 PyInstaller 存档')
        return False


    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver) = \
                struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver, pylibname) = \
                struct.unpack('!8siiii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))

        except:
            print('[*] Error : The file is not a pyinstaller archive / 错误：该文件不是一个 PyInstaller 归档')
            return False

        print('[*] Python version: {0} / Python 版本: {0}'.format(self.pyver))

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print('[*] Length of package: {0} bytes / 包长度: {0} 字节'.format(self.overlaySize))
        return True


    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iiiiBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!iiiBc{0}s'.format(entrySize - nameLen), \
                self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                print('[!] Warning: Found an unamed file in CArchive. Using random name {0} / 警告：在 CArchive 中发现未命名文件。使用随机名称 {0}'.format(name))

            self.tocList.append( \
                                CTOCEntry(                      \
                                    self.overlayPos + entryPos, \
                                    cmprsdDataSize,             \
                                    uncmprsdDataSize,           \
                                    cmprsFlag,                  \
                                    typeCmprsData,              \
                                    name                        \
                                ))

            parsedLen += entrySize
        print('[*] Found {0} files in CArchive / 在 CArchive 中找到 {0} 个文件'.format(len(self.tocList)))


    def extractFiles(self, custom_dir=None):
        print('[*] Beginning extraction...please standby / 开始提取...请稍候')
        if custom_dir is None:
            extractionDir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')

            if not os.path.exists(extractionDir):
                os.mkdir(extractionDir)

            os.chdir(extractionDir)
        else:
            if not os.path.exists(custom_dir):
                os.makedirs(custom_dir)
            os.chdir(custom_dir)

        for entry in self.tocList:
            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize # Sanity Check

            with open(entry.name, 'wb') as f:
                f.write(data)

            if entry.typeCmprsData == b'z':
                self._extractPyz(entry.name)


    def _extractPyz(self, name):
        dirName =  name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0' # Sanity Check

            pycHeader = f.read(4) # Python magic value

            # 使用新的 get_python_magic() 函数替代 imp.get_magic() / Use new get_python_magic() function to replace imp.get_magic()
            current_magic = get_python_magic()
            if current_magic != pycHeader:
                print('[!] Warning: The script is running in a different python version than the one used to build the executable / 警告：脚本运行的 Python 版本与构建可执行文件时使用的版本不同')
                print('    Run this script in Python{0} to prevent extraction errors(if any) during unmarshalling / 请在 Python{0} 中运行此脚本以防止解包过程中出现错误（如果有）'.format(self.pyver))

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print('[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files. / 解包失败。无法提取 {0}。提取剩余文件。'.format(name))
                return

            print('[*] Found {0} files in PYZ archive / 在 PYZ 归档中找到 {0} 个文件'.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)

                fileName = key
                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = key.decode('utf-8')
                except:
                    pass

                # Make sure destination directory exists, ensuring we keep inside dirName
                destName = os.path.join(dirName, fileName.replace("..", "__"))
                destDirName = os.path.dirname(destName)
                if not os.path.exists(destDirName):
                    os.makedirs(destDirName)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is. / 错误：解压 {0} 失败，可能已加密。按原样提取。'.format(fileName))
                    open(destName + '.pyc.encrypted', 'wb').write(data)
                    continue

                with open(destName + '.pyc', 'wb') as pycFile:
                    pycFile.write(pycHeader)      # Write pyc magic
                    pycFile.write(b'\0' * 4)      # Write timestamp
                    if self.pyver >= 33:
                        pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3
                    pycFile.write(data)


def main():
    if len(sys.argv) < 2:
        print('[*] Usage: pyinstxtractor.py <filename> / 用法: pyinstxtractor.py <文件名>')

    else:
        arch = PyInstArchive(sys.argv[1])
        if arch.open():
            if arch.checkFile():
                if arch.getCArchiveInfo():
                    arch.parseTOC()
                    arch.extractFiles()
                    arch.close()
                    print('[*] Successfully extracted pyinstaller archive: {0} / 成功提取 PyInstaller 归档: {0}'.format(sys.argv[1]))
                    print('')
                    print('You can now use a python decompiler on the pyc files within the extracted directory / 现在您可以在提取目录中的 pyc 文件上使用 Python 反编译器')
                    return

            arch.close()


if __name__ == '__main__':
    main()
