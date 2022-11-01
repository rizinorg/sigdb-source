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

class Signature(object):
	def __init__(self, tokens, max_postlude):
		super(Signature, self).__init__()
		self.prelude = tokens[0]
		self.crclen = tokens[1]
		self.crc16 = tokens[2]
		self.funcsize = tokens[3]
		self.offset = tokens[4]
		self.symbol = tokens[5]
		self.postlude = tokens[6] if len(tokens) > 6 else ""

		if len(self.postlude) > max_postlude:
			self.postlude = self.postlude[0:max_postlude]
		self.postlude = self.postlude.rstrip('.')

	def __lt__(self, other):
		if self.signature(False) == other.signature(False):
			return self.signature(True) < other.signature(True)
		return self.signature(False) < other.signature(False)

	def __hash__(self):
		return hash(self.signature(False))

	def __repr__(self):
		return self.signature()

	def __eq__(self, other):
		return self.signature(False) == other.signature(False)

	def __ne__(self, other):
		return (not self.__eq__(other))


	def signature(self, with_symbol=True):
		sig = [
			self.prelude,
			self.crclen,
			self.crc16,
			self.funcsize,
			self.offset
		]
		if with_symbol:
			sig.append(self.symbol)
		if len(self.postlude) > 0:
			sig.append(self.postlude)
		return " ".join(sig)

	def completeness(self):
		mbytes = self.prelude + self.postlude
		masked = mbytes.count('.')
		crc16len = int('0x' + self.crclen, 16)
		percentage = (masked / (len(mbytes) + crc16len)) * 100
		percentage = 100 - percentage
		return percentage


class PatFile(object):
	def __init__(self, outname, max_postlude):
		super(PatFile, self).__init__()
		self.outname = outname
		self.max_postlude = max_postlude * 2
		self.signatures = []

	def generate(self):
		old_len = len(self.signatures)
		self.signatures = list(set(self.signatures))
		self.signatures.sort()
		n_duplicates = old_len - len(self.signatures)
		with open(self.outname, "w") as fp:
			for line in self.signatures:
				fp.write(line.signature() + '\n')
			fp.write("---\n")
		percentage = 0
		if old_len > 0:
			percentage = n_duplicates / old_len * 100
		print("There were {} duplicates out of {} signatures (~{:.0f}%).".format(n_duplicates, old_len, percentage))
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

				s = Signature(line.split(" "), self.max_postlude)
				if is_bad_symbol(s.symbol):
					if verbose:
						print("dropping {} signature due bad symbol name ({:.2f}%)".format(s.signature()))
					continue

				n_signatures += 1

				if s.funcsize == "0000":
					# drop any signature with function size of zero
					if verbose:
						print("dropping {} signature due function size ({:.2f}%)".format(s.signature()))
					n_dropped += 1
					continue
				elif s.prelude == ("." * len(s.prelude)):
					# drop any signature with empty pattern
					if verbose:
						print("dropping {} signature due bad prelude ({:.2f}%)".format(s.signature()))
					n_dropped += 1
					continue

				percentage = s.completeness()
				if percentage < threshold:
					if verbose:
						print("dropping {} signature due bad threshold ({:.2f}%)".format(s.signature(), percentage))
					# drop any signature that does not reach the threshold
					n_dropped += 1
					continue

				self.signatures.append(s)
		return (n_signatures, n_dropped)

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

	if not args.test:
		pat.generate()


if __name__ == '__main__':
	main()
