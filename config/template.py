import os

class template():
    ELF_FILE = ""
    find = []
    avoid = []

    @classmethod
    def elf(cls):
        if os.path.exists(cls.ELF_FILE):
            return cls.ELF_FILE
        else:
            raise Exception("File '{}' not found".format(cls.ELF_FILE))

    def find(self):
        return self.find

    def avoid(self):
        return self.avoid