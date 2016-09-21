#!/usr/bin/env python

# Precompiled binary installer for PyDasm by Mario Vilas
# http://breakingcode.wordpress.com/

from distutils.core import setup
from distutils.util import get_platform
from distutils.errors import DistutilsPlatformError

import sys
import ctypes
import os.path

# Determine the target platform
platform = '%s-%s.%s' % (get_platform(),
                         sys.version_info[0], sys.version_info[1])

# Determine how to copy the precompiled binary.
dlls = os.path.join(sys.prefix, 'DLLs')
pyd = os.path.join(platform, 'pydasm.pyd')
if not os.path.exists(pyd):
    raise DistutilsPlatformError()
if os.path.exists(dlls):
    data_files = [ (dlls, [pyd]) ]
else:
    data_files = [ pyd ]

# Set the parameters for the setup script
params = {

    # Setup instructions
    'provides'      : ['pydasm'],
    'data_files'    : data_files,

    # Metadata
    'name'          : 'PyDasm',
    'version'       : '1.5',
    'description'   : 'Libdasm bindings for Python',
    'url'           : 'http://code.google.com/p/libdasm/',
    'download_url'  : 'http://winappdbg.sourceforge.net/blog/PyDasm-1.5-precompiled.zip',
    'platforms'     : ['win32', 'win64'],
    'classifiers'   : [
                        'License :: Public Domain',
                        'Development Status :: 5 - Production/Stable',
                        'Programming Language :: Python :: 2.6',
                        'Programming Language :: Python :: 2.7',
                        'Topic :: Software Development :: Libraries',
                      ],
    }

# Execute the setup script
if __name__ == '__main__':
    setup(**params)
