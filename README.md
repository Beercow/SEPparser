# SEPparser

Blog post
https://malwaremaloney.blogspot.com/2019/06/introducing-sepparser.html

Tested with python3.6

SEPparser.py \-h\
usage: SEPparser.py [\-h] [\-f FILE] [\-d DIR] [\-e] [\-hd] [\-qd] [\-o OUTPUT] [\-a]\
                                 [-r REGISTRATIONINFO] [-tz TIMEZONE] [-k] [-s]

optional arguments:\
    -h, --help                        show this help message and exit\
    -f FILE, --file FILE            File to be parsed\
    -d DIR, --dir DIR             Directory to be parsed\
    -e, --extract                    Extract quarantine file from VBN if present.\
    -hd, --hex-dump            Dump hex output of VBN to screen.\
    -qd, --quarantine-dump\
                                           Dump hex output of quarantine to screen.\
    -o OUTPUT, --output OUTPUT\
                                           Directory to output files to. Default is current\
                                           directory.\
    -a, --append                   Append to output files.\
    -r REGISTRATIONINFO, --registrationInfo REGISTRATIONINFO\
                                           Path to registrationInfo.xml\
    -tz TIMEZONE, --timezone TIMEZONE\
                                           UTC offset\
    -k, --kape                       Kape mode\
    -s, --struct                      Output structures to csv\
