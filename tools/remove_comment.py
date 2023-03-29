import re
import os
import uuid


def remove_comment(inputFile, outputFile):
    fdr = open(inputFile, 'r', encoding="utf-8")
    fdw = open(outputFile, 'w', encoding="utf-8")
    _map = {}
    outstring = ''

    line = fdr.readline()
    while line:
        while True:
            m = re.compile('\".*\"', re.S)
            _str = m.search(line)
            if None == _str:
                outstring += line
                break
            key = str(uuid.uuid1())
            m = re.compile('\".*\"', re.S)
            outtmp = re.sub(m, key, line, 1)
            line = outtmp
            _map[key] = _str.group(0)
        line = fdr.readline()

    m = re.compile(r'//.*')
    outtmp = re.sub(m, ' ', outstring)
    outstring = outtmp

    m = re.compile(r'/\*.*?\*/', re.S)
    outtmp = re.sub(m, ' ', outstring)
    outstring = outtmp

    for key in _map.keys():
        outstring = outstring.replace(key, _map[key])

    fdw.write(outstring)
    fdw.close()


if __name__ == '__main__':
    original_dir = "../source_code/"
    output_dir = "../clean_source_code/"
    dir = os.listdir(original_dir)
    for i in dir:
        print(i)
        remove_comment(original_dir + i, output_dir + i)
