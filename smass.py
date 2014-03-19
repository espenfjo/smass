import os
from os.path import basename, isfile
import argparse
import logging
import sys

from lib.configreader import parse_config
from lib.Artifact import Artifact



def read_config():
    configfile = "smass.conf"
    parser = argparse.ArgumentParser()
    description='Arguments to start SMASS'

    
    parser.add_argument('--configfile', type=str, nargs=1,
                        help='SMASS configuration file')
    args, remaining_argv = parser.parse_known_args()
    parser.add_argument('--type', type=str, nargs=1,
                        help='Select type of file')
    parser.add_argument('--source', type=str, nargs='?',
                        help='Where the artifact was obtained')
    parser.add_argument('--tags', type=str, nargs='*',
                        help='Tags to describe the artifact')
    parser.add_argument('--comment', type=str, nargs='?',
                        help='Comment(s) describing the artifact')


    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")
    parser.add_argument("-d", "--debug", help="Debug output",
                    action="store_true")

    parser.add_argument('artifact', type=str,
                        help='Path to the artifact')
    if args.configfile:
        configfile = args.configfile

    config = parse_config(configfile)
    parser.set_defaults(**config)
    args = parser.parse_args(remaining_argv)
    return args

config = read_config()
if config.verbose:
    logging.basicConfig(level=logging.INFO)
if config.debug:
    logging.basicConfig(level=logging.DEBUG)


if not isfile(config.artifact):
    logging.critical("Artifact {} not found: no such file or directory".format(config.artifact))
    sys.exit(1)


path = config.artifact
name = basename(config.artifact)
statinfo = os.stat(path)
size = statinfo.st_size

try:
    f = open(config.artifact, "rb")
    data = f.read()
except IOError, e:
    logging.critical("Could not read {}: {} ".format(path, e))
    sys.exit(1)

artifact = Artifact(config, name, size, data)
artifact.analyse()

if not hasattr(artifact, 'report'):
    logging.critical("Analysis report not generated!")
    sys.exit(1)



meta = {
    "source": config.source,
    "tags": config.tags,
    "comment": config.comment
}
artifact.report['meta'] = meta
artifact.database.collection.insert(artifact.report)
