from __future__ import annotations
from enum import Enum
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]

class ByteColor(Enum):
    BLACK = "\x1b[30m"
    BLUE = "\x1b[34m"
    CYAN = "\x1b[36m"
    GREEN = "\x1b[32m"
    LIGHT_GREEN = "\x1b[38;5;190m"
    LIGHT_PINK = "\x1b[38;5;213m"
    LIGHT_BLUE = "\x1b[38;5;81m"
    LIGHT_MAGENTA = "\x1b[38;5;201m"
    LIGHT_CYAN = "\x1b[38;5;39m"
    MAGENTA = "\x1b[35m"
    ORANGE = "\x1b[38;5;208m"
    PINK = "\x1b[35m"
    RED = "\x1b[31m"
    RED_BROWN = "\x1b[38;5;202m"
    WHITE = "\x1b[37m"
    YELLOW = "\x1b[33m"
    YELLOW_GREEN = "\x1b[38;5;190m"


class CipherBlockByte:

    def __init__(self, byte: int):
        self.byte_value = byte
        self.__color = ByteColor.WHITE
        self.__tags = []
        self.__is_placeholder = False

    def __str__(self) -> str:
        if self.is_placeholder:
            value = "??"
        else:
            value = f"{self.byte_value:02x}"

        if self.color != ByteColor.WHITE:
            value = f"{self.color.value}{value}{ByteColor.WHITE.value}"

        return value

    def __eq__(self, other: 'CipherBlockByte') -> bool:
        return self.byte_value == other.byte_value

    def as_base(self, base: int = 16, padding: int = 0) -> str:
        """ Pad then color so the control characters aren't included in the padding."""
        if base == 2:
            value = f"{self.byte_value:08b}".rjust(padding)
        elif base == 8:
            value = f"{self.byte_value:03o}".rjust(padding)
        elif base == 10:
            value = f"{self.byte_value:03d}".rjust(padding)
        elif base == 16:
            value = f"{self.byte_value:02x}".rjust(padding)
        else:
            raise ValueError("Invalid base")
        return f"{self.color.value}{value}{ByteColor.WHITE.value}"

    def set_placeholder(self) -> 'CipherBlockByte':
        self.__is_placeholder = True
        return self

    def clear_placeholder(self) -> 'CipherBlockByte':
        self.__is_placeholder = False
        return self

    def set_color(self, color: ByteColor) -> 'CipherBlockByte':
        self.__color = color
        return self

    def clear_color(self) -> 'CipherBlockByte':
        self.__color = ByteColor.WHITE
        return self

    def tag(self, tag: str) -> 'CipherBlockByte':
        self.__tags.append(tag)
        return self

    def untag(self, tag: str) -> 'CipherBlockByte':
        self.__tags.remove(tag)
        return self

    def has_tag(self, tag: str) -> bool:
        return tag in self.__tags

    def clear_tags(self) -> 'CipherBlockByte':
        self.__tags = []
        return self

    @property
    def color(self) -> ByteColor:
        return self.__color

    @property
    def tags(self) -> list[str]:
        return self.__tags

    @property
    def is_placeholder(self) -> bool:
        return self.__is_placeholder


class CipherBlock:

    def __init__(self, ciphertext: bytes = b"", block_size: int = 16):
        if len(ciphertext) > block_size:
            raise ValueError("Ciphertext length must be less than or equal to block size")
        self.__original_bytes = bytearray(ciphertext)
        self.__block_size = block_size
        self.block_bytes = []
        self.__parse_block_bytes(ciphertext)

    @property
    def block_size(self) -> int:
        return self.__block_size

    @property
    def original_bytes(self) -> bytes:
        return self.__original_bytes

    def from_hex_str(self, hex_string: str) -> 'CipherBlock':
        if len(hex_string) > self.block_size * 2:
            raise ValueError(f"Hex string length must be less than or equal to block size ({self.block_size})")
        self.__parse_block_bytes(bytearray(bytes.fromhex(hex_string)))
        return self

    def as_base(self, base: int = 16, padding: int = 0) -> str:
        return "".join(byte.as_base(base, padding) for byte in self.block_bytes)

    def set_placeholder(self, start_byte: int = 0, end_byte: int = -1) -> 'CipherBlock':
        # Handle negative indices and ensure proper slicing
        if end_byte == -1:
            end_byte = len(self.block_bytes)
        [byte.set_placeholder() for byte in self.block_bytes[start_byte:end_byte]]
        return self

    def clear_placeholder(self) -> 'CipherBlock':
        [byte.clear_placeholder() for byte in self.block_bytes]
        return self

    def set_color(self, color: ByteColor, start_byte: int = 0, end_byte: int = -1) -> 'CipherBlock':
        # Handle negative indices and ensure proper slicing
        if end_byte == -1:
            end_byte = len(self.block_bytes)
        [byte.set_color(color) for byte in self.block_bytes[start_byte:end_byte]]
        return self

    def clear_color(self) -> 'CipherBlock':
        [byte.clear_color() for byte in self.block_bytes]
        return self

    def tag(self, tag: str, start_byte: int = 0, end_byte: int = -1) -> 'CipherBlock':
        # Handle negative indices and ensure proper slicing
        if end_byte == -1:
            end_byte = len(self.block_bytes)
        [byte.tag(tag) for byte in self.block_bytes[start_byte:end_byte]]
        return self

    def untag(self, tag: str) -> 'CipherBlock':
        [byte.untag(tag) for byte in self.block_bytes]
        return self

    def has_tag(self, tag: str, start_byte: int = 0, end_byte: int = -1) -> bool:
        # Handle negative indices and ensure proper slicing
        if end_byte == -1:
            end_byte = len(self.block_bytes)
        return any(byte.has_tag(tag) for byte in self.block_bytes[start_byte:end_byte])

    def clear_tags(self) -> 'CipherBlockByte':
        [byte.clear_tags() for byte in self.block_bytes]
        return self

    def print(self, base: int = 16, spacing: int = 1, padding: int = 0, chunk_size: int = 8, sep: str = "   ") -> None:
        chunks = []
        for i in range(0, len(self.block_bytes), chunk_size):
            padded_bytes = []
            for byte in self.block_bytes[i:i + chunk_size]:
                padded_byte = byte.as_base(base, padding)
                padded_bytes.append(padded_byte)
            whitespace = " " * spacing
            chunk = whitespace.join(padded_bytes)
            chunks.append(chunk)
        print(sep.join(chunks))

    def __parse_block_bytes(self, ciphertext: bytes):
        for i in range(len(ciphertext)):
            self.block_bytes.append(CipherBlockByte(ciphertext[i]))

    def __len__(self) -> int:
        return len(self.block_bytes)

    def __str__(self) -> str:
        return "".join(str(byte) for byte in self.block_bytes)

    def __getitem__(self, index: int) -> CipherBlockByte:
        return self.block_bytes[index]

    def __setitem__(self, index: int, value: int) -> None:
        self.block_bytes[index].byte_value = value

    def __eq__(self, other: 'CipherBlock') -> bool:
        return self.block_bytes == other.block_bytes


class CipherBlockSet:

    def __init__(self, ciphertext: bytes, block_size: int = 16):
        self.__block_size = block_size
        self.__original_bytes = ciphertext
        self.cipher_blocks = []
        self.__parse_blocks(ciphertext)

    def __parse_blocks(self, ciphertext: bytes):
        # Calculate how many complete blocks we can make
        complete_blocks = len(ciphertext) // self.block_size

        # Create complete blocks
        for i in range(complete_blocks):
            block_bytes = ciphertext[i * self.block_size:(i + 1) * self.block_size]
            block = CipherBlock(block_bytes, self.block_size)
            self.cipher_blocks.append(block)

        # Handle remaining bytes as a partial block
        remaining_bytes = len(ciphertext) % self.block_size
        if remaining_bytes > 0:
            start_idx = complete_blocks * self.block_size
            block_bytes = ciphertext[start_idx:]
            block = CipherBlock(block_bytes, self.block_size)
            self.cipher_blocks.append(block)

    @property
    def block_size(self) -> int:
        return self.__block_size

    @property
    def original_bytes(self) -> bytes:
        return self.__original_bytes

    def as_base(self, base: int = 16, padding: int = 0) -> str:
        return "".join(block.as_base(base, padding) for block in self.cipher_blocks)

    def print(self, base: int = 16, spacing: int = 1, padding: int = 0, chunk_size: int = 8, sep: str = "  |  ") -> None:
        for block in self.cipher_blocks:
            block.print(base, spacing, padding, chunk_size, sep)

    def set_placeholder(self, start_block: int = 0, end_block: int = -1) -> 'CipherBlockSet':
        # Handle negative indices and ensure proper slicing
        if end_block == -1:
            end_block = len(self.cipher_blocks)

        # Ensure end_block doesn't exceed the number of blocks
        end_block = min(end_block, len(self.cipher_blocks))

        # For range selection, end_block should be the index after the last block we want to select
        # So start_block=0, end_block=1 means select blocks 0 and 1, which requires slice [0:2]
        # Always increment end_block by 1 to convert from inclusive to exclusive slicing
        end_block = end_block + 1

        [block.set_placeholder() for block in self.cipher_blocks[start_block:end_block]]
        return self

    def clear_placeholder(self) -> 'CipherBlockSet':
        [block.clear_placeholder() for block in self.cipher_blocks]
        return self

    def set_color(self, color: ByteColor, start_block: int = 0, end_block: int = -1) -> 'CipherBlockSet':
        # Handle negative indices and ensure proper slicing
        if end_block == -1:
            end_block = len(self.cipher_blocks)

        # Ensure end_block doesn't exceed the number of blocks
        end_block = min(end_block, len(self.cipher_blocks))

        # For range selection, end_block should be the index after the last block we want to select
        # So start_block=0, end_block=1 means select blocks 0 and 1, which requires slice [0:2]
        # Always increment end_block by 1 to convert from inclusive to exclusive slicing
        end_block = end_block + 1

        selected_blocks = self.cipher_blocks[start_block:end_block]
        [block.set_color(color) for block in selected_blocks]
        return self

    def clear_color(self) -> 'CipherBlockSet':
        [block.clear_color() for block in self.cipher_blocks]
        return self

    def tag(self, tag: str, start_block: int = 0, end_block: int = -1) -> 'CipherBlockSet':
        # Handle negative indices and ensure proper slicing
        if end_block == -1:
            end_block = len(self.cipher_blocks)

        # Ensure end_block doesn't exceed the number of blocks
        end_block = min(end_block, len(self.cipher_blocks))

        # For range selection, end_block should be the index after the last block we want to select
        # So start_block=0, end_block=1 means select blocks 0 and 1, which requires slice [0:2]
        # Always increment end_block by 1 to convert from inclusive to exclusive slicing
        end_block = end_block + 1

        [block.tag(tag) for block in self.cipher_blocks[start_block:end_block]]
        return self

    def untag(self, tag: str, start_block: int = 0, end_block: int = -1) -> 'CipherBlockSet':
        # Handle negative indices and ensure proper slicing
        if end_block == -1:
            end_block = len(self.cipher_blocks)

        # Ensure end_block doesn't exceed the number of blocks
        end_block = min(end_block, len(self.cipher_blocks))

        # For range selection, end_block should be the index after the last block we want to select
        # So start_block=0, end_block=1 means select blocks 0 and 1, which requires slice [0:2]
        # Always increment end_block by 1 to convert from inclusive to exclusive slicing
        end_block = end_block + 1

        [block.untag(tag) for block in self.cipher_blocks[start_block:end_block]]
        return self

    def has_tag(self, tag: str, start_block: int = 0, end_block: int = -1) -> bool:
        # Handle negative indices and ensure proper slicing
        if end_block == -1:
            end_block = len(self.cipher_blocks)

        # Ensure end_block doesn't exceed the number of blocks
        end_block = min(end_block, len(self.cipher_blocks))

        # For range selection, end_block should be the index after the last block we want to select
        # So start_block=0, end_block=1 means select blocks 0 and 1, which requires slice [0:2]
        # Always increment end_block by 1 to convert from inclusive to exclusive slicing
        end_block = end_block + 1

        return any(block.has_tag(tag) for block in self.cipher_blocks[start_block:end_block])

    def clear_tags(self) -> 'CipherBlockSet':
        [block.clear_tags() for block in self.cipher_blocks]
        return self

    def __str__(self) -> str:
        return " ".join(str(block) for block in self.cipher_blocks)

    def __len__(self):
        return len(self.cipher_blocks)

    def __getitem__(self, index):
        return self.cipher_blocks[index]

    def __setitem__(self, index, value):
        if not isinstance(value, CipherBlock):
            raise ValueError("Value must be a CipherBlock")
        self.cipher_blocks[index] = value

    def __iter__(self):
        return iter(self.cipher_blocks)

    def __next__(self):
        return next(self.cipher_blocks)