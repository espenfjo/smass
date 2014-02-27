import magic

class filemagic:
    def __init__(self, artifact):
        self.data = artifact.data
        self.magic = magic.from_buffer(self.data)
        if not self.magic:
            logging.error("Could not load magic information about file")
