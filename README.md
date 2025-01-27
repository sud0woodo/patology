# patology

Python script to decrypt Synology .pat files

## Installation

Install the other dependencies using:

```sh
pip install dissect.cstruct msgpack pysodium
```

## Usage

Using the script is simple as there really are only 2 options; `rebuild` which rebuilds the encrypted `.pat` file to a decrypted `tar` archive, and `dump` which simply dumps the contents of the decrypted archive in the current folder. A little word of caution when using the `dump` option as this will create folders in that same directory as well, so make sure to perform this in an empty directory. The main difference between using these 2 options is that the `rebuild` option will preserve the original `tar` info attributes like the file permission rights and timestamps.

To dump the contents of the archive in the same folder:

```sh
python3 patology.py --infile DSM_DS920+_69057.pat --dump
2024-04-18 21:19:47 - INFO - Opening archive: DSM_DS920+_69057.pat
2024-04-18 21:19:47 - INFO - Verified magic: 0xadbeef
2024-04-18 21:19:47 - INFO - Verified signature: <redacted>
2024-04-18 21:19:47 - INFO - Encrypted data offset: 0x993
2024-04-18 21:19:47 - INFO - ChaCha20 key: <redacted>
2024-04-18 21:19:48 - INFO - Verified msgpack messageblocks
2024-04-18 21:19:48 - INFO - Succesfully decrypted TAR entry headers
2024-04-18 21:19:48 - INFO - Decrypting 60 entries
2024-04-18 21:19:48 - INFO - Successfully decrypted 60 entries
2024-04-18 21:19:48 - INFO - Successfully dumped DiskCompatibilityDB.tar [4194304]
2024-04-18 21:19:48 - INFO - Successfully dumped GRUB_VER [98]
2024-04-18 21:19:48 - INFO - Successfully dumped H2OFFT-Lx64 [1080555]
2024-04-18 21:19:48 - INFO - Successfully dumped VERSION [680]
2024-04-18 21:19:48 - INFO - Successfully dumped autonano.pat [4194304]
...
2024-04-18 21:19:48 - INFO - Succesfully dumped files from archive
2024-04-18 21:19:48 - INFO - msgblock sizes check out, file successfully parsed
2024-04-18 21:19:48 - INFO - Closing archive: DSM_DS920+_69057.pat
```

To rebuild the `tar` archive and write this to the specified output file:

```sh
python3 patology.py --infile DSM_DS920+_69057.pat --rebuild DSM_DS920+_69057.tar
2024-04-18 21:21:48 - INFO - Opening archive: DSM_DS920+_69057.pat
2024-04-18 21:21:48 - INFO - Verified magic: 0xadbeef
2024-04-18 21:21:48 - INFO - Verified signature: <redacted>
2024-04-18 21:21:48 - INFO - Encrypted data offset: 0x993
2024-04-18 21:21:48 - INFO - ChaCha20 key: <redacted>
2024-04-18 21:21:49 - INFO - Verified msgpack messageblocks
2024-04-18 21:21:49 - INFO - Succesfully decrypted TAR entry headers
2024-04-18 21:21:49 - INFO - Decrypting 60 entries
2024-04-18 21:21:49 - INFO - Successfully decrypted 60 entries
2024-04-18 21:21:50 - INFO - Decrypted TAR written to out.tar
2024-04-18 21:21:50 - INFO - msgblock sizes check out, file successfully parsed
2024-04-18 21:21:50 - INFO - Closing archive: DSM_DS920+_69057.pat
```

At the time of writing it really only supports the system patch updates as I haven't looked closely at how the other patch types are currently extracted. Another thing to note is that there might be different archive formats, some formats use a different header magic, just like the different patch types I have not yet looked at how the extraction process is implemented for these and hope to do so in the near future.
