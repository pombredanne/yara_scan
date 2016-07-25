#!/usr/bin/env python
import os
import sys
import argparse
import yara
# yara_scan
# usage: python yara_scan.py -y <yara_rule_dir> [-s <scan_files_dir> (optional otherwise current dir is scanned)]

__author__ = "Tyler Halfpop"
__version__ = "0.2"

def parse_arguments():
    parser = argparse.ArgumentParser(usage="Scan Files in a Directory with Yara Rules")
    parser.add_argument('-y', '--yara_dir',
                        action='store',
                        help='Path to Yara rules directory')

    parser.add_argument('-s', '--scan_dir',
                        action='store',
                        default=os.getcwd(),
                        help='Path to the directory of files to scan')

    return parser

class YaraClass:
    def __init__(self, arg_yara_dir, arg_scan_dir):
        try:
            self.scan_dir = arg_scan_dir
            self.yara_dir = arg_yara_dir
        except Exception as e:
            print "Init Exception: {}".format(e)

    def compile(self):
        try:
            all_rules = {}
            for root, directories, files in os.walk(self.yara_dir):
                for file in files:
                    if "yar" in os.path.splitext(file)[1]:
                        rule_case = os.path.join(root,file) 
                        if self.test_rule(rule_case):
                            all_rules[file] = rule_case
            self.rules = yara.compile(filepaths=all_rules)
        except Exception as e:
            print "Compile Exception: {}".format(e)

    def test_rule(self, test_case):
        try:
            testit = yara.compile(filepath=test_case)
            return True
        except:
            print "{} is an invalid rule".format(test_case)
            return False

    def scan(self):
        try:
            for root, directories, files in os.walk(self.scan_dir):
                for file in files:
                    matches = self.rules.match(os.path.join(root,file))
                    print "{}\n{}\n".format(file, matches)
        except Exception as e:
            print "Scan Exception: {}".format(e)

def main():
    args = parse_arguments().parse_args()

    ys = YaraClass(args.yara_dir, args.scan_dir) 
    ys.compile()
    ys.scan()

if __name__ == "__main__":
    main()
