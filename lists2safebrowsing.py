#!/usr/bin/python

import sys
import os
import time

def main():
  if len(sys.argv) < 4:
    sys.exit("Usage: " + sys.argv[0] + " <handler> <input_directory> <output_file>")

  handler = sys.argv[1]
  input_dir = sys.argv[2]
  output_file = sys.argv[3]
  allowlist_file = None
  if len(sys.argv) > 4:
    allowlist_file = sys.argv[4]

  # initial chunk number, each handler will produce at least one separate
  # chunk (one chunk per list it processes) and each chunk must have a
  # unique chunk number. for now the initial chunk number is the epoch
  chunkInit = time.time();
  chunk = chunkInit;

  # output file,
  # representation of extracted URLs in safebrowsing-list format
  f_out = open(output_file, "wb")

  # log file
  f_log = open(output_file + ".log", "w");

  # load our allowlist
  allowed = set()
  if allowlist_file:
    with open(allowlist_file, "r") as f:
      for line in f:
        line = line.strip()
        # don't add blank lines or comments
        if not line or line.startswith('#'):
          continue
        allowed.add(line)

  print "[+] Processing", os.path.split(input_dir)[1];
  mod = __import__('handler_' + handler)
  chunk = mod.main(input_dir, f_out, f_log, chunk, allowed);

  f_out.close();
  f_log.close();

  print "[+] Produced", (chunk - chunkInit), "chunks"


if __name__ == "__main__":
  main()

