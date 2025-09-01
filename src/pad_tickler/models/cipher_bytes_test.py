import pytest
from pad_tickler.lib.cipher_bytes import CipherBlockByte, CipherBlock, CipherBlockSet, ByteColor


class TestCipherBlockByte:
    """Test suite for CipherBlockByte class"""

    def test_init(self):
        """Test CipherBlockByte initialization"""
        byte = CipherBlockByte(0x41)
        assert byte.byte_value == 0x41

    def test_str_representation(self):
        """Test string representation of CipherBlockByte"""
        byte = CipherBlockByte(0x0A)
        assert str(byte) == "0a"

    def test_str_with_placeholder(self):
        """Test string representation when byte is placeholder"""
        byte = CipherBlockByte(0x41)
        byte.set_placeholder()
        assert str(byte) == "??"

    def test_str_with_color(self):
        """Test string representation with color"""
        byte = CipherBlockByte(0x41)
        byte.set_color(ByteColor.RED)
        result = str(byte)
        assert ByteColor.RED.value in result
        assert ByteColor.WHITE.value in result

    def test_equality(self):
        """Test equality between CipherBlockByte instances"""
        byte1 = CipherBlockByte(0x41)
        byte2 = CipherBlockByte(0x41)
        byte3 = CipherBlockByte(0x42)

        assert byte1 == byte2
        assert byte1 != byte3

    def test_as_base_hex(self):
        """Test as_base method with hex (base 16)"""
        byte = CipherBlockByte(0x0A)
        result = byte.as_base(base=16, padding=4)
        # Account for ANSI color codes
        assert "0a" in result
        assert ByteColor.WHITE.value in result

    def test_as_base_decimal(self):
        """Test as_base method with decimal (base 10)"""
        byte = CipherBlockByte(0x0A)
        result = byte.as_base(base=10, padding=4)
        # Account for ANSI color codes
        assert "010" in result
        assert ByteColor.WHITE.value in result

    def test_as_base_binary(self):
        """Test as_base method with binary (base 2)"""
        byte = CipherBlockByte(0x0A)
        result = byte.as_base(base=2, padding=8)
        assert "00001010" in result

    def test_as_base_octal(self):
        """Test as_base method with octal (base 8)"""
        byte = CipherBlockByte(0x0A)
        result = byte.as_base(base=8, padding=4)
        # Account for ANSI color codes
        assert "012" in result
        assert ByteColor.WHITE.value in result

    def test_invalid_base(self):
        """Test as_base method with invalid base"""
        byte = CipherBlockByte(0x41)
        with pytest.raises(ValueError, match="Invalid base"):
            byte.as_base(base=7)

    def test_placeholder_operations(self):
        """Test placeholder setting and clearing"""
        byte = CipherBlockByte(0x41)
        assert not byte.is_placeholder

        byte.set_placeholder()
        assert byte.is_placeholder

        byte.clear_placeholder()
        assert not byte.is_placeholder

    def test_color_operations(self):
        """Test color setting and clearing"""
        byte = CipherBlockByte(0x41)
        assert byte.color == ByteColor.WHITE

        byte.set_color(ByteColor.RED)
        assert byte.color == ByteColor.RED

        byte.clear_color()
        assert byte.color == ByteColor.WHITE

    def test_tag_operations(self):
        """Test tag operations"""
        byte = CipherBlockByte(0x41)

        # Test adding tag
        byte.tag("test")
        assert byte.has_tag("test")
        assert not byte.has_tag("test2")

        # Test removing tag
        byte.untag("test")
        assert not byte.has_tag("test")

        # Test clearing all tags
        byte.tag("tag1")
        byte.tag("tag2")
        byte.clear_tags()
        assert not byte.has_tag("tag1")
        assert not byte.has_tag("tag2")


class TestCipherBlock:
    """Test suite for CipherBlock class"""

    def test_init_with_bytes(self):
        """Test CipherBlock initialization with bytes"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data, block_size=16)
        assert len(block) == 4
        assert block.block_size == 16

    def test_init_with_empty_bytes(self):
        """Test CipherBlock initialization with empty bytes"""
        block = CipherBlock(block_size=16)
        assert len(block) == 0
        assert block.block_size == 16

    def test_init_with_too_large_data(self):
        """Test CipherBlock initialization with data larger than block size"""
        data = b"\x01" * 17  # 17 bytes, larger than default 16
        with pytest.raises(ValueError, match="Ciphertext length must be less than or equal to block size"):
            CipherBlock(data, block_size=16)

    def test_from_hex_str(self):
        """Test from_hex_str method"""
        block = CipherBlock()
        result = block.from_hex_str("0102030405060708090a0b0c0d0e0f10")
        assert len(result) == 16
        assert result[0] == 0x01
        assert result[15] == 0x10

    def test_from_hex_str_too_long(self):
        """Test from_hex_str with hex string too long for block size"""
        block = CipherBlock(block_size=8)
        with pytest.raises(ValueError, match="Hex string length must be less than or equal to block size"):
            block.from_hex_str("0102030405060708090a0b0c0d0e0f10")

    def test_str_representation(self):
        """Test string representation of CipherBlock"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)
        assert str(block) == "01020304"

    def test_length(self):
        """Test length of CipherBlock"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)
        assert len(block) == 4

    def test_indexing(self):
        """Test indexing operations"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)

        assert block[0] == 0x01
        assert block[3] == 0x04
        assert block[-1] == 0x04

    def test_index_assignment(self):
        """Test index assignment"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)

        block[0] = 0xFF
        assert block[0] == 0xFF

    def test_equality(self):
        """Test equality between CipherBlock instances"""
        data1 = b"\x01\x02\x03\x04"
        data2 = b"\x01\x02\x03\x04"
        data3 = b"\x01\x02\x03\x05"

        block1 = CipherBlock(data1)
        block2 = CipherBlock(data2)
        block3 = CipherBlock(data3)

        assert block1 == block2
        assert block1 != block3

    def test_as_base(self):
        """Test as_base method"""
        data = b"\x01\x02"
        block = CipherBlock(data)
        result = block.as_base(base=16, padding=4)
        # Account for ANSI color codes
        assert "01" in result
        assert "02" in result
        assert ByteColor.WHITE.value in result

    def test_placeholder_operations(self):
        """Test placeholder operations on CipherBlock"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)

        # Test setting placeholder
        result = block.set_placeholder()
        assert result == block
        assert all(byte.is_placeholder for byte in block.block_bytes)

        # Test clearing placeholder
        result = block.clear_placeholder()
        assert result == block
        assert not any(byte.is_placeholder for byte in block.block_bytes)

    def test_color_operations(self):
        """Test color operations on CipherBlock"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)

        # Test setting color
        result = block.set_color(ByteColor.RED)
        assert result == block
        assert all(byte.color == ByteColor.RED for byte in block.block_bytes)

        # Test clearing color
        result = block.clear_color()
        assert result == block
        assert all(byte.color == ByteColor.WHITE for byte in block.block_bytes)

    def test_tag_operations(self):
        """Test tag operations on CipherBlock"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)

        # Test adding tag
        result = block.tag("test")
        assert result == block
        assert all(byte.has_tag("test") for byte in block.block_bytes)

        # Test removing tag
        result = block.untag("test")
        assert result == block
        assert not any(byte.has_tag("test") for byte in block.block_bytes)

    def test_has_tag(self):
        """Test has_tag method"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)

        assert not block.has_tag("test")
        block.tag("test")
        assert block.has_tag("test")

    def test_clear_tags(self):
        """Test clear_tags method"""
        data = b"\x01\x02\x03\x04"
        block = CipherBlock(data)

        block.tag("tag1")
        block.tag("tag2")
        result = block.clear_tags()
        assert result == block
        assert not block.has_tag("tag1")
        assert not block.has_tag("tag2")


class TestCipherBlockSet:
    """Test suite for CipherBlockSet class"""

    def test_init(self):
        """Test CipherBlockSet initialization"""
        data = b"\x01" * 32  # 32 bytes = 2 blocks of 16
        blockset = CipherBlockSet(data, block_size=16)
        assert len(blockset) == 2
        assert blockset.block_size == 16

    def test_init_with_custom_block_size(self):
        """Test CipherBlockSet initialization with custom block size"""
        data = b"\x01" * 24  # 24 bytes = 3 blocks of 8
        blockset = CipherBlockSet(data, block_size=8)
        assert len(blockset) == 3
        assert blockset.block_size == 8

    def test_parse_blocks(self):
        """Test that blocks are parsed correctly"""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" + \
               b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
        blockset = CipherBlockSet(data, block_size=16)

        assert len(blockset) == 2
        assert str(blockset[0]) == "0102030405060708090a0b0c0d0e0f10"
        assert str(blockset[1]) == "1112131415161718191a1b1c1d1e1f20"

    def test_str_representation(self):
        """Test string representation of CipherBlockSet"""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" + \
               b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
        blockset = CipherBlockSet(data, block_size=16)

        result = str(blockset)
        assert "0102030405060708090a0b0c0d0e0f10" in result
        assert "1112131415161718191a1b1c1d1e1f20" in result

    def test_indexing(self):
        """Test indexing operations on CipherBlockSet"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        assert isinstance(blockset[0], CipherBlock)
        assert isinstance(blockset[1], CipherBlock)

    def test_index_assignment(self):
        """Test index assignment on CipherBlockSet"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        new_block = CipherBlock(b"\xFF" * 16)
        blockset[0] = new_block
        assert blockset[0] == new_block

    def test_index_assignment_invalid_type(self):
        """Test index assignment with invalid type"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        with pytest.raises(ValueError, match="Value must be a CipherBlock"):
            blockset[0] = "invalid"

    def test_iteration(self):
        """Test iteration over CipherBlockSet"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        blocks = list(blockset)
        assert len(blocks) == 2
        assert all(isinstance(block, CipherBlock) for block in blocks)

    def test_as_base(self):
        """Test as_base method"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        result = blockset.as_base(base=16, padding=4)
        # Account for ANSI color codes
        assert "01" in result
        assert ByteColor.WHITE.value in result

    def test_placeholder_operations(self):
        """Test placeholder operations on CipherBlockSet"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        # Test setting placeholder
        result = blockset.set_placeholder()
        assert result == blockset
        # Check that all bytes in all blocks have placeholder set
        assert all(byte.is_placeholder for block in blockset for byte in block.block_bytes)

        # Test clearing placeholder
        result = blockset.clear_placeholder()
        assert result == blockset
        assert not any(byte.is_placeholder for block in blockset for byte in block.block_bytes)

    def test_color_operations(self):
        """Test color operations on CipherBlockSet"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        # Test setting color
        result = blockset.set_color(ByteColor.RED)
        assert result == blockset
        # Check that all bytes in all blocks have the color set
        assert all(byte.color == ByteColor.RED for block in blockset for byte in block.block_bytes)

        # Test clearing color
        result = blockset.clear_color()
        assert result == blockset
        assert all(byte.color == ByteColor.WHITE for block in blockset for byte in block.block_bytes)

    def test_tag_operations(self):
        """Test tag operations on CipherBlockSet"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        # Test adding tag
        result = blockset.tag("test")
        assert result == blockset
        assert blockset.has_tag("test")

        # Test removing tag
        result = blockset.untag("test")
        assert result == blockset
        assert not blockset.has_tag("test")

    def test_has_tag(self):
        """Test has_tag method"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        assert not blockset.has_tag("test")
        blockset.tag("test")
        assert blockset.has_tag("test")

    def test_clear_tags(self):
        """Test clear_tags method"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)

        blockset.tag("tag1")
        blockset.tag("tag2")
        result = blockset.clear_tags()
        assert result == blockset
        assert not blockset.has_tag("tag1")
        assert not blockset.has_tag("tag2")

    def test_block_level_color_operations_with_ranges(self):
        """Test block-level color operations with start_block and end_block parameters"""
        data = b"\x01" * 48  # 48 bytes = 3 blocks of 16
        blockset = CipherBlockSet(data, block_size=16)

        # Verify we have 3 blocks
        assert len(blockset) == 3, f"Expected 3 blocks, got {len(blockset)}"

        # Test coloring single block (start_block == end_block)
        blockset.set_color(ByteColor.RED, start_block=1, end_block=1)
        print(f"After coloring block 1 - Block 0 colors: {[byte.color for byte in blockset[0].block_bytes[:3]]}")
        print(f"After coloring block 1 - Block 1 colors: {[byte.color for byte in blockset[1].block_bytes[:3]]}")
        print(f"After coloring block 1 - Block 2 colors: {[byte.color for byte in blockset[2].block_bytes[:3]]}")

        # Block 0 should remain white
        assert all(byte.color == ByteColor.WHITE for byte in blockset[0].block_bytes)
        # Block 1 should be red
        assert all(byte.color == ByteColor.RED for byte in blockset[1].block_bytes)
        # Block 2 should remain white
        assert all(byte.color == ByteColor.WHITE for byte in blockset[2].block_bytes)

        # Test coloring range of blocks
        blockset.clear_color()
        print(f"After clear_color - Block 0 colors: {[byte.color for byte in blockset[0].block_bytes[:3]]}")
        print(f"After clear_color - Block 1 colors: {[byte.color for byte in blockset[1].block_bytes[:3]]}")

        blockset.set_color(ByteColor.BLUE, start_block=0, end_block=1)
        print(f"After set_color blue - Block 0 colors: {[byte.color for byte in blockset[0].block_bytes[:3]]}")
        print(f"After set_color blue - Block 1 colors: {[byte.color for byte in blockset[1].block_bytes[:3]]}")

        # Blocks 0 and 1 should be blue
        assert all(byte.color == ByteColor.BLUE for byte in blockset[0].block_bytes)
        assert all(byte.color == ByteColor.BLUE for byte in blockset[1].block_bytes)
        # Block 2 should remain white
        assert all(byte.color == ByteColor.WHITE for byte in blockset[2].block_bytes)

        # Test coloring all blocks with negative indexing
        blockset.clear_color()
        blockset.set_color(ByteColor.GREEN, start_block=0, end_block=-1)
        # All blocks should be green
        assert all(byte.color == ByteColor.GREEN for block in blockset for byte in block.block_bytes)

        # Test coloring from middle to end
        blockset.clear_color()
        blockset.set_color(ByteColor.YELLOW, start_block=1, end_block=-1)
        # Block 0 should remain white
        assert all(byte.color == ByteColor.WHITE for byte in blockset[0].block_bytes)
        # Blocks 1 and 2 should be yellow
        assert all(byte.color == ByteColor.YELLOW for byte in blockset[1].block_bytes)
        assert all(byte.color == ByteColor.YELLOW for byte in blockset[2].block_bytes)

    def test_block_level_tag_operations_with_ranges(self):
        """Test block-level tag operations with start_block and end_block parameters"""
        data = b"\x01" * 48  # 48 bytes = 3 blocks of 16
        blockset = CipherBlockSet(data, block_size=16)

        # Verify we have 3 blocks
        assert len(blockset) == 3, f"Expected 3 blocks, got {len(blockset)}"

        # Test tagging single block (start_block == end_block)
        blockset.tag("important", start_block=1, end_block=1)
        # Block 0 should not have the tag
        assert not blockset[0].has_tag("important")
        # Block 1 should have the tag
        assert blockset[1].has_tag("important")
        # Block 2 should not have the tag
        assert not blockset[2].has_tag("important")

        # Test tagging range of blocks
        blockset.clear_tags()
        blockset.tag("critical", start_block=0, end_block=1)
        # Blocks 0 and 1 should have the tag
        assert blockset[0].has_tag("critical")
        assert blockset[1].has_tag("critical")
        # Block 2 should not have the tag
        assert not blockset[2].has_tag("critical")

        # Test tagging all blocks with negative indexing
        blockset.clear_tags()
        blockset.tag("urgent", start_block=0, end_block=-1)
        # All blocks should have the tag
        assert all(block.has_tag("urgent") for block in blockset)

        # Test untagging specific blocks
        blockset.untag("urgent", start_block=1, end_block=1)
        # Block 0 should still have the tag
        assert blockset[0].has_tag("urgent")
        # Block 1 should not have the tag
        assert not blockset[1].has_tag("urgent")
        # Block 2 should still have the tag
        assert blockset[2].has_tag("urgent")

    def test_block_level_placeholder_operations_with_ranges(self):
        """Test block-level placeholder operations with start_block and end_block parameters"""
        data = b"\x01" * 48  # 48 bytes = 3 blocks of 16
        blockset = CipherBlockSet(data, block_size=16)

        # Verify we have 3 blocks
        assert len(blockset) == 3, f"Expected 3 blocks, got {len(blockset)}"

        # Test setting placeholder on single block (start_block == end_block)
        blockset.set_placeholder(start_block=1, end_block=1)
        # Block 0 should not have placeholders
        assert not any(byte.is_placeholder for byte in blockset[0].block_bytes)
        # Block 1 should have placeholders
        assert all(byte.is_placeholder for byte in blockset[1].block_bytes)
        # Block 2 should not have placeholders
        assert not any(byte.is_placeholder for byte in blockset[2].block_bytes)

        # Test setting placeholder on range of blocks
        blockset.clear_placeholder()
        blockset.set_placeholder(start_block=0, end_block=1)
        # Blocks 0 and 1 should have placeholders
        assert all(byte.is_placeholder for byte in blockset[0].block_bytes)
        assert all(byte.is_placeholder for byte in blockset[1].block_bytes)
        # Block 2 should not have placeholders
        assert not any(byte.is_placeholder for byte in blockset[2].block_bytes)

        # Test setting placeholder on all blocks with negative indexing
        blockset.clear_placeholder()
        blockset.set_placeholder(start_block=0, end_block=-1)
        # All blocks should have placeholders
        assert all(byte.is_placeholder for block in blockset for byte in block.block_bytes)

    def test_edge_cases_for_block_ranges(self):
        """Test edge cases for block range operations"""
        data = b"\x01" * 32  # 32 bytes = 2 blocks of 16
        blockset = CipherBlockSet(data, block_size=16)

        # Test with start_block > end_block (should result in no blocks selected)
        blockset.set_color(ByteColor.RED, start_block=1, end_block=0)
        # No blocks should be colored
        assert all(byte.color == ByteColor.WHITE for block in blockset for byte in block.block_bytes)

        # Test with start_block == end_block == 0
        blockset.set_color(ByteColor.BLUE, start_block=0, end_block=0)
        # Only block 0 should be colored
        assert all(byte.color == ByteColor.BLUE for byte in blockset[0].block_bytes)
        assert all(byte.color == ByteColor.WHITE for byte in blockset[1].block_bytes)

        # Test with start_block == end_block == 1
        blockset.clear_color()
        blockset.set_color(ByteColor.GREEN, start_block=1, end_block=1)
        # Only block 1 should be colored
        assert all(byte.color == ByteColor.WHITE for byte in blockset[0].block_bytes)
        assert all(byte.color == ByteColor.GREEN for byte in blockset[1].block_bytes)

        # Test with end_block exceeding block count
        blockset.clear_color()
        blockset.set_color(ByteColor.YELLOW, start_block=0, end_block=5)
        # All blocks should be colored (end_block is clamped to 2)
        assert all(byte.color == ByteColor.YELLOW for block in blockset for byte in block.block_bytes)

    def test_negative_indexing_for_block_ranges(self):
        """Test negative indexing for block range operations"""
        data = b"\x01" * 48  # 48 bytes = 3 blocks of 16
        blockset = CipherBlockSet(data, block_size=16)

        # Verify we have 3 blocks
        assert len(blockset) == 3, f"Expected 3 blocks, got {len(blockset)}"

        # Test with end_block = -1 (last block)
        blockset.set_color(ByteColor.RED, start_block=0, end_block=-1)
        # All blocks should be colored
        assert all(byte.color == ByteColor.RED for block in blockset for byte in block.block_bytes)

        # Test with end_block = -2 (second-to-last block)
        blockset.clear_color()
        blockset.set_color(ByteColor.BLUE, start_block=0, end_block=-2)
        # Blocks 0 and 1 should be colored
        assert all(byte.color == ByteColor.BLUE for byte in blockset[0].block_bytes)
        assert all(byte.color == ByteColor.BLUE for byte in blockset[1].block_bytes)
        # Block 2 should remain white
        assert all(byte.color == ByteColor.WHITE for byte in blockset[2].block_bytes)

        # Test with start_block = -2, end_block = -1
        blockset.clear_color()
        blockset.set_color(ByteColor.GREEN, start_block=-2, end_block=-1)
        # Block 1 should be colored
        assert all(byte.color == ByteColor.WHITE for byte in blockset[0].block_bytes)
        assert all(byte.color == ByteColor.GREEN for byte in blockset[1].block_bytes)
        # Block 2 should be colored
        assert all(byte.color == ByteColor.GREEN for byte in blockset[2].block_bytes)

    def test_has_tag_with_block_ranges(self):
        """Test has_tag method with block ranges"""
        data = b"\x01" * 48  # 48 bytes = 3 blocks of 16
        blockset = CipherBlockSet(data, block_size=16)

        # Verify we have 3 blocks
        assert len(blockset) == 3, f"Expected 3 blocks, got {len(blockset)}"

        # Tag only block 1
        blockset.tag("test", start_block=1, end_block=1)

        # Check if specific blocks have the tag
        assert not blockset.has_tag("test", start_block=0, end_block=0)  # Block 0
        assert blockset.has_tag("test", start_block=1, end_block=1)      # Block 1
        assert not blockset.has_tag("test", start_block=2, end_block=2)  # Block 2

        # Check if range of blocks has the tag
        assert blockset.has_tag("test", start_block=0, end_block=1)      # Blocks 0-1
        assert blockset.has_tag("test", start_block=1, end_block=2)      # Blocks 1-2
        assert blockset.has_tag("test", start_block=0, end_block=2)      # All blocks

        # Tag all blocks and test
        blockset.clear_tags()
        blockset.tag("test", start_block=0, end_block=-1)
        assert blockset.has_tag("test", start_block=0, end_block=0)      # Block 0
        assert blockset.has_tag("test", start_block=1, end_block=1)      # Block 1
        assert blockset.has_tag("test", start_block=2, end_block=2)      # Block 2

    def test_original_bytes_property(self):
        """Test original_bytes property"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=16)
        assert blockset.original_bytes == data

    def test_block_size_property(self):
        """Test block_size property"""
        data = b"\x01" * 32
        blockset = CipherBlockSet(data, block_size=8)
        assert blockset.block_size == 8


class TestIntegration:
    """Integration tests combining multiple classes"""

    def test_cipherblock_in_cipherblockset(self):
        """Test that CipherBlock instances work correctly within CipherBlockSet"""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" + \
               b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
        blockset = CipherBlockSet(data, block_size=16)

        # Modify a byte in the first block
        blockset[0][0] = 0xFF
        assert blockset[0][0] == 0xFF

        # The modification should be reflected in the string representation
        assert "ff" in str(blockset[0])

    def test_color_propagation(self):
        """Test that colors are properly applied to individual bytes"""
        data = b"\x01" * 16
        block = CipherBlock(data)

        # Set color on specific byte
        block.block_bytes[0].set_color(ByteColor.RED)
        assert block.block_bytes[0].color == ByteColor.RED

        # Other bytes should remain unchanged
        assert block.block_bytes[1].color == ByteColor.WHITE

    def test_tag_propagation(self):
        """Test that tags are properly applied to individual bytes"""
        data = b"\x01" * 16
        block = CipherBlock(data)

        # Set tag on specific byte
        block.block_bytes[0].tag("important")
        assert block.block_bytes[0].has_tag("important")

        # Other bytes should not have the tag
        assert not block.block_bytes[1].has_tag("important")
