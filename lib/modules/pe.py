import base64
import datetime
import hashlib
import logging
import magic
import os
import pefile
import re

class pe(object):
    def __init__(self, artifact):
        self.type = "pe"
        self.artifact = artifact.data
        self.data = {}
        self.data["name"] = "PE"
        self.data["_model"] = self.data["name"]
        self.data["_module"] = "analysis.models"

    def init(self):
        try:
            self.pe = pefile.PE(data=self.artifact)
        except pefile.PEFormatError as e:
            logging.error("Unable to parse PE file: {0}".format(e))
            return

        self.imports()
        self.exports()
        self.compile_time()
        self.resources()
        self.imphash()
        self.machine()
        self.data['section_numbers'] = self.pe.FILE_HEADER.NumberOfSections
        self.sections()
        self.data['entrypoint'] = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint


    def sections(self):
        sections = []
        for section in self.pe.sections:
            name = section.Name
            virtual_address = hex(section.VirtualAddress)
            virtual_size = hex(section.Misc_VirtualSize)
            raw_size = section.SizeOfRawData
            md5 = section.get_hash_md5()
            entropy = section.get_entropy()
            sections.append({'name': name, 'virtual_address':virtual_address, 'virtual_size':virtual_size, 'raw_size':raw_size, 'md5':md5, 'entropy':entropy})
        self.data['sections'] = sections

    def string_table(self):
        string_data = {}
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        string_data[entry[0]] = entry[1]


    def machine(self):
         if hasattr(self.pe, 'FILE_HEADER'):
             machine = hex(self.pe.FILE_HEADER.Machine)

             if machine == "0x14c":
                 self.data["machine"] = "Intel 386 or later processors and compatible processors"
             elif machine == "0x8664":
                 self.data["machine"] = "x64"
             elif machine == "0x1c0":
                 self.data["machine"] = "ARM little endian"
             elif machine == "0x1c4":
                 self.data["machine"] = "ARMv7 (or higher) Thumb mode only"
             elif machine == "0xebc":
                 self.data["machine"] = "EFI byte code"
             elif machine == "0x0200":
                 self.data["machine"] = "Intel Itanium"
             else:
                 self.data["machine"] = machine

    # Use this function to retrieve resources for the given PE instance.
    # Returns all the identified resources with indicators and attributes.
    def resources(self):
        resources = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    resource = {}

                    if resource_type.name is not None:
                        name = str(resource_type.name)
                    else:
                        name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))

                    if name == None:
                        name = str(resource_type.struct.Id)

                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    filetype = self.__get_filetype(data)
                                    md5 = self.__get_md5(data)
                                    language = pefile.LANG.get(resource_lang.data.lang, None)
                                    sublanguage = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                                    offset = ('%-8s' % hex(resource_lang.data.struct.OffsetToData)).strip()
                                    size = ('%-8s' % hex(resource_lang.data.struct.Size)).strip()
                                    resource = {
                                        "name": name,
                                        "filetype": filetype,
                                        "offset": offset,
                                        "size": size,
                                        "md5": md5,
                                        "language": language,
                                        "sublanguage": sublanguage,
                                        #"data": base64.b64encode(data)
                                    }

                                    resources.append(resource)
                except Exception as e:
                    logging.error(e)
                    continue

            self.data["sub"] = resources

    def imphash(self):
        self.data['imphash'] = self.pe.get_imphash()

    def imports(self):
        dlls = []
        if not self.pe:
            return

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = {"name": entry.dll, "imports": [], "jquery_proof_name": entry.dll.replace('.', '_')}
                try:
                    for symbol in entry.imports:
                        symbol_import = {"address": hex(symbol.address), "name": symbol.name}
                        dll["imports"].append(symbol_import)
                except:
                    continue
                dlls.append(dll)
            self.data["imports"] = dlls


    def exports(self):
        exports = []
        if not self.pe:
            return

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append("{0}: {1} ({2})".format(hex(self.pe.OPTIONAL_HEADER.ImageBase + symbol.address), symbol.name, symbol.ordinal))

        self.data["exports"] = exports

    def compile_time(self):
        compile_time = datetime.datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)
        self.data["compile_time"] = compile_time

    def __get_md5(self, data):
        md5 = hashlib.md5()
        md5.update(data)
        return md5.hexdigest()

    def __get_filetype(self, data):
        try:
            file_type = magic.from_buffer(data)
        except Exception:
            return None

        return file_type