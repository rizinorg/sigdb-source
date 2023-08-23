#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import sys
import os
import glob
import argparse


def esc(code):
    return f"\033[{code}m"


DESCRIPTION = "Rizin source signature database linter"
EPILOG = ""
TEST_XX = esc(31) + "XX" + esc(0)
TEST_OK = esc(32) + "OK" + esc(0)


def is_empty_file(dirpath, subfpath):
    return os.path.getsize(os.path.join(dirpath, subfpath)) < 2


def is_file_of(dirpath, subfpath):
    return os.path.isfile(os.path.join(dirpath, subfpath))


def test_text(dirpath, subfpath, verbose):
    errored = False
    if not is_file_of(dirpath, subfpath):
        errored = True
        print(f"[{TEST_XX}] {subfpath}: does not exists.")
    elif is_empty_file(dirpath, subfpath):
        errored = True
        print(f"[{TEST_XX}] {subfpath}: is empty.")

    if not errored and verbose:
        print(f"[{TEST_OK}] {subfpath}")

    return errored


def test_sha1(dirpath, subfpath, verbose):
    errored = False
    if not is_file_of(dirpath, subfpath):
        errored = True
        print(f"[{TEST_XX}] {subfpath} does not exists.")
    elif is_empty_file(dirpath, subfpath):
        errored = True
        print(f"[{TEST_XX}] {subfpath} is empty.")
    else:
        filename = os.path.join(dirpath, subfpath)
        with open(filename, "r") as fp:
            line_no = 0
            for line in fp:
                line_no += 1
                tokens = line.strip().split()
                length = len(tokens)
                if length != 2:
                    errored = True
                    print(
                        f"[{TEST_XX}] {subfpath}:{line_no}: expected 2 tokens but {length} has been parsed."
                    )
                length = len(tokens[0])
                if length != 40:
                    errored = True
                    print(
                        f"[{TEST_XX}] {subfpath}:{line_no}: hash appears to not be sha1 (expected 40 chars but had {length})"
                    )

    if not errored and verbose:
        print(f"[{TEST_OK}] {subfpath}")

    return errored


def main():
    parser = argparse.ArgumentParser(
        usage="%(prog)s [options] directory",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("directory", help="path to sigdb-source")
    parser.add_argument(
        "-v", "--verbose", default=False, help="verbose", action="store_true"
    )
    args = parser.parse_args()

    if args.directory == None or not os.path.isdir(args.directory):
        print("Error: invalid arguments: path is invalid or not a folder.")
        print("usage: python linter.py /path/to/sigdb-source")
        sys.exit(1)

    has_failed = False

    root_dir = os.path.abspath(args.directory)
    for directory in os.listdir(path=root_dir):
        dirpath = os.path.join(root_dir, directory)

        if directory.startswith(".") or not os.path.isdir(dirpath):
            # ignore any file or any directory starting with .
            continue

        for subpath in glob.glob("*/*/*", root_dir=dirpath, recursive=False):
            libname = os.path.basename(subpath)
            pat_path = os.path.join(subpath, libname + ".pat")
            descr_path = os.path.join(subpath, libname + ".description")
            sha1_path = os.path.join(subpath, libname + ".src.sha1")

            if test_text(dirpath, pat_path, args.verbose):
                has_failed = True

            if test_text(dirpath, descr_path, args.verbose):
                has_failed = True

            if test_sha1(dirpath, sha1_path, args.verbose):
                has_failed = True

    if has_failed:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
