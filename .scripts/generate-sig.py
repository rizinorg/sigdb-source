# SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
# SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import sys
import os

DESCRIPTION='Rizin FLIRT signature database generator for sig files'
EPILOG='''
This tool generates .sig files from the sigdb-source database
Example:
	$ mkdir build-sig
	$ python generate-sig.py --rz-sign /path/to/rz-sign --source /path/to/sigdb-source/ --output build-sig
'''

def system_die(cmd):
	ret = os.system(cmd)
	if ret != 0:
		print("Error: command '{}' returned exit code {}".format(cmd, ret))
		sys.exit(1)

def file_exists_or_die(path):
	if os.path.isfile(path):
		return
	print("Error: '{}' does not exists".format(path))
	sys.exit(1)

def read_description_or_die(path):
	with open(path) as fp:
		desc = fp.readline().strip().replace("'", '')
		if len(desc) > 0:
			return desc
		print("Error: '{}' contains an invalid or empty description".format(path))
		sys.exit(1)

def listdirs(path):
	d = [name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]
	d.sort()
	return d

class SigMake(object):
	def __init__(self, file_in, file_out, lib_desc, lib_arch, lib_bits):
		super(SigMake, self).__init__()
		self.file_in = file_in
		self.file_out = file_out
		self.lib_desc = lib_desc
		self.lib_arch = lib_arch
		self.lib_bits = lib_bits

	def generate(self, rz_sign, test):
		print('Generating {} signature (as {}) from {}'.format(self.lib_desc, os.path.basename(self.file_out), os.path.basename(self.file_in)))
		if not test:
			system_die("{} -q -e 'flirt.sig.deflate=true' -e 'asm.arch={}' -e 'asm.bits={}' -e 'flirt.sig.library={} (rizin.re)' -c '{}' '{}'".format(rz_sign, self.lib_arch, self.lib_bits, self.lib_desc, self.file_out, self.file_in))

def main():
	parser = argparse.ArgumentParser(usage='%(prog)s [options]', description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('-s', '--source', default='', help='path to sigdb-source directory (it has to point to sigdb-source root dir)')
	parser.add_argument('-o', '--output', default='', help='path to the output directory')
	parser.add_argument('-r', '--rz-sign', default='rz-sign', help='rz-sign binary path')
	parser.add_argument('--overwrite', default=False, help='allowes overwriting the output files', action='store_true')
	parser.add_argument('--test', default=False, help='simulates the generation but does not create the files', action='store_true')
	args = parser.parse_args()

	if len(sys.argv) == 1 or \
		len(args.source) < 1 or \
		len(args.output) < 1 or \
		len(args.rz_sign) < 1:
		parser.print_help(sys.stderr)
		sys.exit(1)

	archs = {}
	sigdb_src = os.path.abspath(args.source)
	sigdb_out = os.path.abspath(args.output)

	if not os.path.isdir(sigdb_src):
		print("Error: path '{}' does not exists".format(sigdb_src))
		sys.exit(1)
	elif not os.path.isdir(sigdb_out):
		print("Error: path '{}' does not exists".format(sigdb_out))
		sys.exit(1)
	elif not args.test and not args.overwrite and len(listdirs(sigdb_out)) > 0:
		print("Error: '{}' already contains some folders. please use an empty folder".format(sigdb_out))
		sys.exit(1)

	print("source:", sigdb_src)
	print("output:", sigdb_out)

	pats = []
	formats = listdirs(sigdb_src)
	for frmt in formats:
		if frmt.startswith("."):
			# we ignore any folder starting with .
			# this is needed for allowing CI data
			# to be stored in the root folder of
			# the repository
			continue
		frmt_src = os.path.join(sigdb_src, frmt)
		archs = listdirs(frmt_src)
		for arch in archs:
			arch_src = os.path.join(frmt_src, arch)
			abits = listdirs(arch_src)
			for bits in abits:
				bits_src = os.path.join(arch_src, bits)
				outdir = os.path.join(sigdb_out, frmt, arch, bits)
				if not args.test and not os.path.isdir(outdir):
					os.makedirs(outdir)
				libs = listdirs(bits_src)
				for lib in libs:
					lib_src = os.path.join(bits_src, lib, lib + ".pat")
					lib_dsc = os.path.join(bits_src, lib, lib + ".description")
					lib_out = os.path.join(sigdb_out, frmt, arch, bits, lib + ".sig")
					file_exists_or_die(lib_src)
					file_exists_or_die(lib_dsc)
					description = read_description_or_die(lib_dsc)
					pats.append(SigMake(lib_src, lib_out, description, arch, bits))

	for pat in pats:
		pat.generate(args.rz_sign, args.test)

if __name__ == '__main__':
	main()
