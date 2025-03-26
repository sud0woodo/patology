from __future__ import annotations

import argparse
import logging
import struct
import tarfile
from collections import OrderedDict
from hashlib import blake2b
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

import msgpack
import pysodium
from dissect.cstruct import cstruct

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
)


try:
    pysodium.crypto_kdf_derive_from_key
except ImportError:
    logging.error(
        "Pysodium package doesn't support crypto_kdf_derive_from_key, git clone and install pysodium: https://github.com/stef/pysodium.git"
    )
    exit(1)


archive_def = """
struct archive_entry_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag[1];
    char linkname[100];
    char magic[6];
};

struct gnu_sparse {
    char offset[12];
    char numbytes[12];
};

struct archive_entry_header_gnutar {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag[1];
    char linkname[100];
    char magic[8];  /* "ustar  \0" (note blank/blank/null at end) */
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char atime[12];
    char ctime[12];
    char offset[12];
    char longnames[4];
    char unused[1];
    struct gnu_sparse sparse[4];
    char isextended[1];
    char realsize[12];
    /*
    * Old GNU format doesn't use POSIX 'prefix' field; they use
    * the 'L' (longname) entry instead.
    */
};
"""

tar_cstruct = cstruct()
tar_cstruct = tar_cstruct.load(archive_def)


# Public key used for the public key verification of the messages
PUBLIC_KEY = bytes.fromhex(
    "64faba48feec6c8a2484d2489a11418a0e980317a9cc6b392f1041925b293fe0"
)

# Master key used for patch files with type 0 or type 10
SUBKEY = bytes.fromhex(
    "078a7529a07a998cffadb87d7378993b7d9ccfa7171f5c47f150838a6a7caf61"
)


def atol(s: str, size: int) -> int:
    """Convert ASCII to integer.

    Args:
        s: The string with numbers to convert to integer.
        size: The size of the string or field.

    Returns:
        The converted string as an integer.
    """
    return int(s.strip() or "0", 8)


class Synocrack:
    """Base class for decrypting and decompressing Synology .pat files.

    Args:
        archive: A file-like object of a .pat archive.
        outfile: The filename to write the decrypted TAR archive to.
    """

    TAR_BLOCKSIZE = 0x200
    CHACHA20_HEADERSIZE = 24

    MAGIC_OFFSET = 0
    MSGPACK_HEADER_LENGTH_OFFSET = 4
    SIGNATURE_LENGTH = 64

    # Fields in the `TarInfo` object that need to be converted to an integer
    TARINFO_FIELDS = {
        "name": False,
        "size": True,
        "mtime": True,
        "mode": False,
        "linkname": False,
        "uid": True,
        "gid": True,
        "uname": False,
        "gname": False,
        "devmajor": True,
        "devminor": False,
    }

    def __init__(self, archive: BinaryIO, outfile: str = ""):
        self.archive = archive
        self.outfile = outfile
        self.entries = OrderedDict()

        # Start of the encrypted TAR archive
        self.encrypted_tar_offset = 0

        # msgpack attributes
        self.msgpack_header = b""
        self.msgpack_messages = []
        # A list of entries in the archive list(entry_offset, entry_hash)
        self.messageblocks = []

        self._magic_check()
        self._verify_signature()

        # ChaCha20 attributes
        self.chacha20_key = b""
        self._derive_key()

        # Check if none of the blocks are corrupt or incomplete
        self._verify_msgpack_blocks()

        # Parse the encrypted archive
        self.entries = {}
        self._parse()

    def rebuild(self):
        """Parse the Synology patch file and rebuild a decrypted TAR archive of its contents."""

        outfile = tarfile.open(self.outfile, "w")
        for entry in self.entries.values():
            tarinfo = entry["header"]
            # The final entry size differs from the size used to decrypt the entry
            tarinfo.size = len(entry["entry"])
            outfile.addfile(tarinfo, fileobj=BytesIO(entry["entry"]))

        logging.info(f"Decrypted TAR written to {self.outfile}")
        outfile.close()

    def dump(self):
        """Dump the contents directory without writing a new TAR."""

        for name, entry in self.entries.items():
            if "/" in name:
                # Create the directory for the file if it doesn't exist
                outfile = Path(name)
                outfile.parent.mkdir(exist_ok=True, parents=True)

            with open(name, "wb") as fh:
                fh.write(entry["entry"])
                logging.info(f"Successfully dumped {name} [{len(entry['entry'])}]")

        logging.info("Succesfully dumped files from archive")

    def _parse(self):
        """Parse the Synology patch file and decrypt its contents."""

        # Decrypt the headers
        self.archive.seek(self.encrypted_tar_offset)
        self._decrypt_tar_headers()
        logging.info(f"Succesfully decrypted TAR entry headers")

        logging.info(f"Decrypting {len(self.entries)} entries")
        for name, fields in self.entries.items():
            decrypted_entry = self._decrypt_tar_entry(
                entry_offset=fields["archive_offset"], entry_size=fields["size"]
            )
            self.entries[name]["entry"] = decrypted_entry

        logging.info(f"Successfully decrypted {len(self.entries)} entries")

    def _magic_check(self):
        """Check if the correct magic is found in the header."""

        self.archive.seek(self.MAGIC_OFFSET)
        magic = struct.unpack(">I", self.archive.read(4))[0] & 0xFFFFFF
        if magic != 0xADBEEF:
            raise ValueError(f"Invalid magic found: 0x{magic:02x}")

        logging.info(f"Verified magic: 0x{magic:02x}")

    def _verify_signature(self):
        """Check the signature of the first msgpack message against the hardcoded public key."""

        self.archive.seek(self.MSGPACK_HEADER_LENGTH_OFFSET)
        # Read the first msgpack message
        header_length = struct.unpack("<I", self.archive.read(4))[0]
        self.msgpack_header = self.archive.read(header_length)
        # Read the message signature for public key verification
        signature = self.archive.read(self.SIGNATURE_LENGTH)

        try:
            pysodium.crypto_sign_verify_detached(
                sig=signature, msg=self.msgpack_header, pk=PUBLIC_KEY
            )
        except ValueError:
            raise ValueError(f"Invalid signature: {signature}")

        logging.info(f"Verified signature: {signature.hex()}")

        # All data after this point belongs to the encrypted entries
        self.encrypted_tar_offset = self.archive.tell()
        logging.info(f"Encrypted data offset: 0x{self.encrypted_tar_offset:02x}")

    def _derive_key(self):
        """Derive the key used for the ChaCha20 decryption that is used later in the decompression process.

        Depending on the type of .pat file a different subkey will be used. The subkey that is currently set is
        for the full system patch files.
        """

        # Unpack the msgpack objects
        self.msgpack_messages.extend(msgpack.unpack(BytesIO(self.msgpack_header)))
        self.messageblocks.append([0, self.msgpack_messages[0]])
        self.messageblocks.extend(self.msgpack_messages[1])
        msgpack_object = self.msgpack_messages[0][::-1]

        # Derive the ChaCha20 key that is used for the decryption of the archive
        subkey_id = struct.unpack(">Q", msgpack_object[0x8 : 0x8 + 8])[0]
        ctx = (
            msgpack_object[0x1 : 0x1 + 7][::-1] + b"\x00"
        )  # Pad the context to 8 bytes
        self.chacha20_key = pysodium.crypto_kdf_derive_from_key(
            len(SUBKEY), subkey_id, ctx, SUBKEY
        )

        logging.info(f"ChaCha20 key: {self.chacha20_key.hex()}")

    def _verify_msgpack_blocks(self):
        """Verify the msgpack blocks to make sure none are corrupt or incomplete.

        Every messageblock entry consists of the length of the messageblack as it's first entry,
        and the blake2b hash of its contents.

        Raises:
            A `ValueError` when a messageblock fails the hash verification check.
        """

        self.archive.seek(self.encrypted_tar_offset)
        for idx, message in enumerate(self.messageblocks[1::]):
            enc_entry = self.archive.read(message[0])
            blake = blake2b(digest_size=32)
            blake.update(enc_entry)
            blake_hash = blake.hexdigest()

            if blake_hash != message[1].hex():
                raise ValueError(
                    f"msgpack block {idx} failed verification [{blake_hash}]"
                )

        logging.info(f"Verified msgpack messageblocks")

    def _decrypt_tar_headers(self):
        """Handle the decryption of each TAR entry header.

        Raises:
            `NotImplementedError` if an archive is found that is not yet supported by this script.
            `ValueError` if one of the pysodium crypto functions fails with the given input.
        """

        for msgblock in self.messageblocks:
            entry_offset = msgblock[0]
            offset = self.archive.tell() + entry_offset
            self.archive.seek(offset)

            chacha20_header = self.archive.read(self.CHACHA20_HEADERSIZE)
            if not chacha20_header:
                return

            try:
                chacha20_state = (
                    pysodium.crypto_secretstream_xchacha20poly1305_init_pull(
                        chacha20_header,
                        self.chacha20_key,
                    )
                )
            except ValueError as e:
                logging.error(
                    f"Error crypto_secretstream_xchacha20poly1305_init_pull: {str(e)} header: {chacha20_header.hex()}"
                )
                return

            # Why 403 bytes you say? I don't know.
            enc_header = self.archive.read(0x193)
            try:
                # Returns the decrypted header and the tag to check if the decryption was successful
                decrypted_header, _ = (
                    pysodium.crypto_secretstream_xchacha20poly1305_pull(
                        chacha20_state,
                        enc_header,
                        b"",
                    )
                )
            except ValueError:
                logging.error(
                    f"Failed to decrypt ciphertext. state: {chacha20_state.hex()} - key: {self.chacha20_key.hex()}"
                )
                return

            archive_header = tar_cstruct.archive_entry_header(decrypted_header)
            if archive_header.magic.decode() == "ustar ":
                # GNU tar format
                # Pad the header, they didn't bother reading a full header for some reason
                decrypted_header += b"\x00" * (
                    self.TAR_BLOCKSIZE % len(decrypted_header)
                )
                archive_header = tar_cstruct.archive_entry_header_gnutar(
                    decrypted_header
                )
            else:
                raise NotImplementedError(
                    f"Unsupported format: {archive_header.magic.decode()}"
                )

            # Set the attributes for the tarinfo
            tarinfo = tarfile.TarInfo()
            for field, needs_atol in self.TARINFO_FIELDS.items():
                value = getattr(archive_header, field)
                tarinfo = self._decode_header_field(
                    tarinfo=tarinfo, field=field, value=value, needs_atol=needs_atol
                )

            self.entries[getattr(tarinfo, "name")] = {
                "size": getattr(tarinfo, "size"),
                "entry_offset": entry_offset,
                "archive_offset": offset,
                "header": tarinfo,
                "entry": None,
            }

            # Reset the pointer
            self.archive.seek(offset)

    def _decode_header_field(
        self,
        tarinfo: tarfile.TarInfo,
        field: str,
        value: bytes,
        needs_atol: bool = False,
    ) -> tarfile.TarInfo:
        """Decode the field in the TAR entry header. Some fields need to be converted to an integer (needs_atol).

        Args:
            tarinfo: A `TarInfo` object of which the attribute needs to be set.
            field: The name of the field.
            value: The value of the field.
            needs_atol: Indicates whether the field needs to be converted to an integer after decoding.

        Returns:
            A `TarInfo` object with the attributes set to the given values from the TAR entry header.
        """

        value = value.decode().split("\x00")[0]

        if needs_atol:
            # Convert the string to an integer for fields that have this set
            value = atol(s=value, size=12)

        if field == "mode":
            # Convert the mode field to an integer value without atol
            value = int(value)

        setattr(tarinfo, field, value)
        return tarinfo

    def _decrypt_tar_entry(self, entry_offset: int, entry_size: int) -> bytes:
        """Handle the decryption of each entry in the TAR archive.

        Args:
            entry_offset: The offset of the entry relative to the current offset + blocksize.
            entry_size: The size of the entry as specified in the header.

        Returns:
            The file within the archive in `bytes`.
        """

        decrypted_buffer = []

        # Seek to the start of the TAR entry
        self.archive.seek(entry_offset + self.TAR_BLOCKSIZE)
        chacha20_header = self.archive.read(self.CHACHA20_HEADERSIZE)
        chacha20_state = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(
            chacha20_header, self.chacha20_key
        )

        bytes_remaining = entry_size
        while bytes_remaining > 0:
            size = min(0x400000, bytes_remaining)
            # For reasons unknown we add 17
            size += 17

            encrypted_buffer = self.archive.read(size)
            try:
                # Returns the decrypted buffer and the tag to check if the decryption was successful
                decrypted, _ = pysodium.crypto_secretstream_xchacha20poly1305_pull(
                    chacha20_state, encrypted_buffer, b""
                )
            except ValueError:
                logging.error(
                    f"Failed to decrypt buffer of entry with offset: 0x{entry_offset:02x}"
                )
                return b""

            decrypted_buffer.append(decrypted)
            bytes_remaining -= len(decrypted)

        return b"".join(decrypted_buffer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--infile", required=True, help="Synology .pat file")
    parser.add_argument(
        "-r",
        "--rebuild",
        required=False,
        help="Rebuild the encrypted .pat file to a decrypted TAR archive",
    )
    parser.add_argument(
        "-d",
        "--dump",
        required=False,
        action="store_true",
        help="Dump the files in the archive to the current directory",
    )

    args = parser.parse_args()

    if not args.rebuild and not args.dump:
        logging.error(f"No valid arguments found, use --rebuild or --dump")
        exit(1)

    logging.info(f"Opening archive: {args.infile}")
    archive = open(args.infile, "rb")
    archive_size = len(archive.read())
    archive.seek(0)

    synocrack = Synocrack(archive=archive, outfile=args.rebuild)

    if args.rebuild:
        synocrack.rebuild()
    else:
        synocrack.dump()

    # Check if we read the complete archive
    if archive.tell() != archive_size:
        raise ValueError(f"{archive_size - archive.tell()} bytes left unread")
    else:
        logging.info(f"msgblock sizes check out, file successfully parsed")

    logging.info(f"Closing archive: {args.infile}")
    archive.close()


if __name__ == "__main__":
    main()
