#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import sys
import os
import glob
from difflib import SequenceMatcher

DESCRIPTION='Rizin FLIRT signature database generator for pat files'
EPILOG='''
This tool generates .pat files from one .pat or multiple .pat
Example:
	# Find arch, bits and format
	$ rz-asm -L | grep tricore
	_dA_  32         tricore     GPL3    Siemens TriCore CPU
	$ rz-bin -L | grep ELF
	bin  elf         ELF format plugin (LGPL3)  

	# Create folders and files
	$ mkdir -p sigdb-source/elf/tricore/32/mylibrary
	$ cp signatures.pat 
	$ echo "My Library Description" > sigdb-source/elf/tricore/32/mylibrary.description
	$ sha1sum tricore-lib.a > sigdb-source/elf/tricore/32/mylibrary.src.sha1

	# Resolve automatically conflicts and generate the final pat file
	$ python .scripts/generate-pat.py --auto --input /path/to/file.pat --input /path/to/file2.pat --output sigdb-source/elf/tricore/32/mylibrary/mylibrary.pat
'''

BAD_SYMBOLS_BEG=['case.0x', 'case.default.0x', 'fcn.', 'loc.', 'sub.', 'reloc.']
BAD_SYMBOLS_END=[]
BAD_SYMBOLS_ALL=['', 'entry0']

def is_bad_symbol(name):
	for beg in BAD_SYMBOLS_BEG:
		if name.startswith(beg):
			return True
	for end in BAD_SYMBOLS_END:
		if name.endswith(end):
			return True
	for sym in BAD_SYMBOLS_ALL:
		if name == sym:
			return True
	return False

def is_pat(file):
	return file.endswith('.pat') and os.path.isfile(file)

def list_pat_files(path, recursive):
	if recursive:
		return  [os.path.join(path, name) for name in glob.glob("**/*.pat", root_dir=path, recursive=True)]
	return list(filter(is_pat, [os.path.join(path, name) for name in os.listdir(path) if os.path.isfile(os.path.join(path, name))]))

def similarity_group(grp):
	avg = 0
	cnt = 0
	for a in grp:
		for b in grp:
			if a == b:
				continue
			avg += SequenceMatcher(None, a, b).ratio()
			cnt += 1
	if cnt < 1:
		# means the names in grp are the same.
		return 1.0
	return avg / cnt

def calculate_stat_bytes(tokens):
	mbytes = tokens[0]
	if len(tokens) > 6:
		mbytes += tokens[6]
	masked = mbytes.count('.')
	percentage = (masked / len(mbytes)) * 100
	percentage = 100 - percentage
	return percentage

class PatFile(object):
	def __init__(self, outname, max_postlude):
		super(PatFile, self).__init__()
		self.outname = outname
		self.max_postlude = max_postlude * 2
		self.signatures = {}

	def generate(self):
		lines = []
		for crc in self.signatures:
			for pre in self.signatures[crc]:
				lines.append(self.signatures[crc][pre] + "\n")

		lines.sort()
		with open(self.outname, "w") as fp:
			for line in lines:
				fp.write(line)
			fp.write("---\n")
		print("{} has been created".format(self.outname))

	def parse(self, filepath, threshold, verbose):
		if verbose:
			print("Parsing {}".format(filepath))
		n_signatures = 0
		n_dropped = 0
		with open(filepath) as fp:
			for line in fp:
				line = line.strip()
				if line.startswith('#') or line == "":
					# ignore any comment on unofficial pat formats
					continue
				elif line == "---":
					break

				tokens = line.split(" ")
				if is_bad_symbol(tokens[5]):
					continue

				n_signatures += 1

				if tokens[3] == "0000":
					# drop any signature with function size of zero
					n_dropped += 1
					continue
				elif tokens[0] == ("." * len(tokens[0])):
					# drop any signature with empty pattern
					n_dropped += 1
					continue

				key = " ".join(tokens[1:3])
				prelude = tokens[0]

				if len(tokens) > 6:
					if self.max_postlude == 0:
						# drop any postlude
						tokens.pop(6)
					elif len(tokens[6]) > self.max_postlude:
						# shorting the postlude
						tokens[6] = tokens[6][0:self.max_postlude]

					tokens[6] = tokens[6].rstrip('.')
					if tokens[6] == ("." * len(tokens[6])):
						# drop any postlude with empty pattern
						tokens.pop(6)

				percentage = calculate_stat_bytes(tokens)
				if percentage < threshold:
					if verbose:
						print("dropping {} signature due bad threshold ({:.2f}%)".format(" ".join(tokens), percentage))
					# drop any signature that does not reach the threshold
					n_dropped += 1
					continue

				if not key in self.signatures:
					self.signatures[key] = {}
					self.signatures[key][prelude] = set()
				elif not prelude in self.signatures[key]:
					self.signatures[key][prelude] = set()

				self.signatures[key][prelude].add(" ".join(tokens))
		return (n_signatures, n_dropped)

	def handle_conflicts(self, resolve, threshold, verbose):
		n_dropped = 0
		n_resolved = 0
		n_total = 0
		for crc in self.signatures:
			to_drop = []
			for prelude in self.signatures[crc]:
				self.signatures[crc][prelude] = list(self.signatures[crc][prelude])
				self.signatures[crc][prelude].sort()
				n_sigs = len(self.signatures[crc][prelude])
				n_total += n_sigs
				if n_sigs < 2:
					self.signatures[crc][prelude] = self.signatures[crc][prelude][0]
					continue
				if not resolve:
					fcns = [s.split(" ")[5] for s in self.signatures[crc][prelude]]
					print("Error: found conflicts on short prelude {} ({})".format(prelude, ', '.join(fcns)))
					sys.exit(1)
				to_drop.append(prelude)

			for prelude in to_drop:
				n_sigs = len(self.signatures[crc][prelude])
				fcns = [s.split(" ")[5] for s in self.signatures[crc][prelude]]
				if crc == "00 0000":
					# too small functions gets always dropped when conflicts are found
					if verbose:
						print("[{}] dropping {} signatures with short prelude {} ({}) due multiple conflicts".format(crc, n_sigs, prelude, ', '.join(fcns)))
					del self.signatures[crc][prelude]
					n_dropped += n_sigs
					continue

				simgrp = similarity_group(fcns)
				if simgrp < threshold:
					if verbose:
						print("[{}] dropping {} signatures with prelude {} ({}) due similarity of {:.2f}".format(crc, n_sigs, prelude, ', '.join(fcns), simgrp))
					del self.signatures[crc][prelude]
					n_dropped += n_sigs
					continue

				n_resolved += n_sigs
				self.signatures[crc][prelude] = self.signatures[crc][prelude][0]
				if verbose:
					print("[{}] keeping {} signatures with prelude {} ({}) and similarity of {}".format(crc, n_sigs, prelude, ', '.join(fcns), simgrp))

		if n_total < 1:
			print("Error: the script could not find and load any valid pat file (use --verbose to have more details)")
			sys.exit(1)

		print("Stats: {} conflicts over a total of {} unique signatures.".format(n_dropped + n_resolved, n_total))
		print("- Resolved: ", n_resolved)
		print("- Dropped:  ", n_dropped)
		print("- Kept:     ", n_total - n_dropped)

def main():
	parser = argparse.ArgumentParser(usage='%(prog)s [options]', description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-d', '--directory', action='append', default=[], help='input directory containing .pat files to parse')
	parser.add_argument('-i', '--input', action='append', default=[], help='input .pat file to parse')
	parser.add_argument('-o', '--output', default='', help='path to the output file .pat')
	parser.add_argument('-t', '--threshold', default=0.66, type=float, help='threshold for similarity (default 0.66, and must be between 0 and 1)')
	parser.add_argument('-p', '--max-postlude', default=64, type=int, help='max postlude pattern max size (default 64)')
	parser.add_argument('-m', '--max-masked', default=50, type=int, help='max masked bytes percentage (default 50%%)')
	parser.add_argument('--auto', default=False, help='tries to auto resolve conflicts by comparing name similarity value against the threshold', action='store_true')
	parser.add_argument('--test', default=False, help='simulates the generation but does not create the files', action='store_true')
	parser.add_argument('--overwrite', default=False, help='allowes overwriting the output file', action='store_true')
	parser.add_argument('--verbose', default=False, help='the script output is verbose', action='store_true')
	parser.add_argument('--recursive', default=False, help='search recursively in the input directory', action='store_true')
	args = parser.parse_args()

	if len(sys.argv) == 1 or \
		(len(args.input) < 1 and len(args.directory) < 1) or \
		len(args.output) < 1 or \
		args.threshold <= 0 or \
		args.threshold >= 1 or \
		args.max_postlude < 0:
		parser.print_help(sys.stderr)
		sys.exit(1)

	maxlen = 0
	infiles = list(args.input)
	for infile in infiles:
		if not is_pat(infile):
			print("Error: '{}' is not a .pat file.".format(infile))
			sys.exit(1)
		maxlen = max(maxlen, len(infile))

	for folder in args.directory:
		if not os.path.isdir(folder):
			print("Error: '{}' is not a directory/folder.".format(folder))
			sys.exit(1)
		infiles += list_pat_files(folder, args.recursive)

	if os.path.isfile(args.output) and not args.overwrite and not args.test:
		print("Error: '{}' does exists. (overwrite is not allowed)".format(args.output))
		sys.exit(1)

	if args.output in infiles:
		print("Info: removed {} from input files.".format(args.output))
		infiles.remove(args.output)

	if len(infiles) < 1:
		print("Error: no pat files has been given in input or were found in the given directories")
		sys.exit(1)

	if args.verbose:
		if args.auto:
			print("threshold: {:.2f}".format(args.threshold))
			print("max postlude: {}".format(args.max_postlude))
			print("max masked: {}".format(args.max_masked))
		print("output: ", args.output)
		print("input:\n    {}".format("\n    ".join(infiles)))
	else:
		print("output:", args.output)
		print("input:  {} pat files".format(len(infiles)))

	n_signatures = 0
	n_dropped = 0
	pat = PatFile(args.output, args.max_postlude)
	for infile in infiles:
		print("        {}\rparsing {}".format(" " * maxlen, infile), end='\r', flush=True)
		n_sigs, n_drops = pat.parse(infile, args.max_masked, args.verbose)
		n_signatures += n_sigs
		n_dropped += n_drops
		maxlen = max(maxlen, len(infile))

	percentage = 0
	if n_signatures > 0:
		percentage = n_dropped / n_signatures * 100
	print("        {}\rparsed a total of {} signatures and dropped {} (~{:.0f}%) signatures.".format(" " * maxlen, n_signatures, n_dropped, percentage), flush=True)

	print("        {}\rhandling conflicts".format(" " * maxlen), flush=True)
	pat.handle_conflicts(args.auto, args.threshold, args.verbose)

	if not args.test:
		pat.generate()

if __name__ == '__main__':
	main()
