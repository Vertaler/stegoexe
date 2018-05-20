from simple_stego import insert_message, extract_message
from optparse import OptionParser
import stego_obfus

if __name__ == "__main__":
    stego_obfus.insert_message('12', 'functions.exe')
    print stego_obfus.extract_message('modified.exe')
    parser = OptionParser()
    parser.add_option("-c", "--container", dest="container", help="path to container", metavar='CONTAINER')
    parser.add_option("-o", "--out",
                      dest="outpath",
                      help="save container with inserted message at OUTPATH",
                      metavar="OUTPATH"
    )
    parser.add_option('-m', '--message', dest="message", help='message inserting to CONTAINER', metavar='MESSAGE')
    parser.add_option('-i', '--insert', action='store_true', dest='insert', help='insert message to CONTAINER')
    parser.add_option('-e', '--extract', action='store_false', dest='insert', help='extract message from CONTAINER')
    options, _ = parser.parse_args()
    if not options.container:
        parser.error('Path to container not given')
    if options.insert:
        outpath = options.outpath
        if not outpath:
            outpath = options.container
        if not options.message:
            parser.error('Message not given')
        insert_message(options.message, options.container, outpath)
    else:
        print extract_message(options.container)