class CipherBlockSet:
    def __init__(self, content: bytes = b"", block_size: int = 16, block_count: int = 0, placeholder_fill: bool = False):
        """ Initialize with either content or block_count """
        self.raw_content = content
        self.block_size = block_size
        self.byte_count = len(content)
        self.blocks = []
        self.block_itr = 0
        self.byte_itr = 0

        if content:
            self.block_count = self.byte_count // self.block_size
            for i in range(self.block_count):
                self.blocks.append(self.raw_content[i * self.block_size:(i + 1) * self.block_size])
        else:
            self.block_count = block_count

    def current_block(self):
        return self.blocks[self.block_itr]

    def current_byte(self):
        return self.blocks[self.block_itr][self.byte_itr]

    def hex(self):
        return self.raw_content.hex()

    def hex_pretty(self):
        return [block.hex() for block in self.blocks]

    def __len__(self):
        return len(self.raw_content)

    def __str__(self):
        return self.raw_content.hex()
