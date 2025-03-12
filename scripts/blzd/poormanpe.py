class PEOffset(IntEnum):
    """Enum for PE header and section offsets."""

    E_LFANEW = 0x3C  # Offset to PE header from DOS header
    NUM_OF_SECTIONS = 6  # Number of sections (inside PE header)
    SIZE_OF_OPTIONAL_HEADER = 20  # Size of optional header (inside PE header)
    FIRST_SECTION_HEADER = 24  # Start of section headers (relative to optional header)

    # Offsets inside the Optional Header
    BASE_OF_CODE = 0x2C  # BaseOfCode (start of .text section)
    IMAGE_BASE = 0x34  # ImageBase (base address of the PE in memory)
    EXPORT_TABLE_OFFSET = 0x78  # Export Table RVA
    IMPORT_TABLE_OFFSET = 0x80  # Import Table RVA
    RESOURCE_TABLE_OFFSET = 0x88  # Resource Table RVA


class SectionOffset(IntEnum):
    """Enum for section header offsets."""

    NAME = 0x00  # Section name (8 bytes)
    VIRTUAL_SIZE = 0x08  # Virtual size in memory
    SIZE_OF_RAW_DATA = 0x10  # Size of section data on disk
    POINTER_TO_RAW_DATA = 0x14  # File offset of section data
    SECTION_HEADER_SIZE = 40  # Size of one section header


@dataclass
class PEHeader:
    """Encapsulates PE header parsing in IDA Pro."""

    pe_data: bytes  # Raw PE header bytes
    image_base: int = field(default_factory=idaapi.get_imagebase)

    @property
    def e_lfanew(self) -> int:
        """Returns the offset of the PE header (from DOS stub)."""
        return struct.unpack(
            "I", self.pe_data[PEOffset.E_LFANEW : PEOffset.E_LFANEW + 4]
        )[0]

    @property
    def pe_header_offset(self) -> int:
        """Returns the absolute address of the PE header."""
        return self.image_base + self.e_lfanew

    @property
    def num_sections(self) -> int:
        """Returns the number of sections in the PE file."""
        return struct.unpack(
            "H",
            self.pe_data[
                self.e_lfanew
                + PEOffset.NUM_OF_SECTIONS : self.e_lfanew
                + PEOffset.NUM_OF_SECTIONS
                + 2
            ],
        )[0]

    @property
    def size_of_optional_header(self) -> int:
        """Returns the size of the optional header."""
        return struct.unpack(
            "H",
            self.pe_data[
                self.e_lfanew
                + PEOffset.SIZE_OF_OPTIONAL_HEADER : self.e_lfanew
                + PEOffset.SIZE_OF_OPTIONAL_HEADER
                + 2
            ],
        )[0]

    @property
    def first_section_offset(self) -> int:
        """Returns the file offset of the first section header."""
        return (
            self.e_lfanew + PEOffset.FIRST_SECTION_HEADER + self.size_of_optional_header
        )

    @property
    def base_of_code(self) -> int:
        """Returns BaseOfCode (start of .text section)."""
        return struct.unpack(
            "I",
            self.pe_data[
                self.e_lfanew
                + PEOffset.BASE_OF_CODE : self.e_lfanew
                + PEOffset.BASE_OF_CODE
                + 4
            ],
        )[0]

    @property
    def import_table_rva(self) -> int:
        """Returns the Import Table RVA."""
        return struct.unpack(
            "I",
            self.pe_data[
                self.e_lfanew
                + PEOffset.IMPORT_TABLE_OFFSET : self.e_lfanew
                + PEOffset.IMPORT_TABLE_OFFSET
                + 4
            ],
        )[0]

    @property
    def export_table_rva(self) -> int:
        """Returns the Export Table RVA."""
        return struct.unpack(
            "I",
            self.pe_data[
                self.e_lfanew
                + PEOffset.EXPORT_TABLE_OFFSET : self.e_lfanew
                + PEOffset.EXPORT_TABLE_OFFSET
                + 4
            ],
        )[0]

    @property
    def resource_table_rva(self) -> int:
        """Returns the Resource Table RVA."""
        return struct.unpack(
            "I",
            self.pe_data[
                self.e_lfanew
                + PEOffset.RESOURCE_TABLE_OFFSET : self.e_lfanew
                + PEOffset.RESOURCE_TABLE_OFFSET
                + 4
            ],
        )[0]


@dataclass
class PESection:
    """Data class to store PE section attributes."""

    name: str
    virtual_size: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    mismatch: Optional[str] = None  # Optional warning message


@dataclass
class PEParser:
    """Parses and exposes PE header and section information."""

    pe_header: PEHeader

    def get_sections(self) -> List[PESection]:
        """Extracts and returns PE sections as dataclasses."""
        sections = []
        for i in range(self.pe_header.num_sections):
            section_start = self.pe_header.first_section_offset + (
                i * SectionOffset.SECTION_HEADER_SIZE
            )

            # Read section name (8 bytes)
            section_name = (
                self.pe_header.pe_data[
                    section_start
                    + SectionOffset.NAME : section_start
                    + SectionOffset.NAME
                    + 8
                ]
                .decode("utf-8", "ignore")
                .strip("\x00")
            )

            # Read VirtualSize (offset 0x08)
            virtual_size = struct.unpack(
                "I",
                self.pe_header.pe_data[
                    section_start
                    + SectionOffset.VIRTUAL_SIZE : section_start
                    + SectionOffset.VIRTUAL_SIZE
                    + 4
                ],
            )[0]

            # Read SizeOfRawData (offset 0x10)
            size_of_raw_data = struct.unpack(
                "I",
                self.pe_header.pe_data[
                    section_start
                    + SectionOffset.SIZE_OF_RAW_DATA : section_start
                    + SectionOffset.SIZE_OF_RAW_DATA
                    + 4
                ],
            )[0]

            # Read PointerToRawData (offset 0x14) - file offset of section data
            pointer_to_raw_data = struct.unpack(
                "I",
                self.pe_header.pe_data[
                    section_start
                    + SectionOffset.POINTER_TO_RAW_DATA : section_start
                    + SectionOffset.POINTER_TO_RAW_DATA
                    + 4
                ],
            )[0]

            # Detect mismatches
            mismatch = None
            if size_of_raw_data < virtual_size:
                mismatch = (
                    "WARNING: SizeOfRawData < VirtualSize (zero-padded in memory)"
                )
            elif size_of_raw_data > virtual_size:
                mismatch = "WARNING: SizeOfRawData > VirtualSize (extra data on disk)"

            sections.append(
                PESection(
                    name=section_name,
                    virtual_size=virtual_size,
                    size_of_raw_data=size_of_raw_data,
                    pointer_to_raw_data=pointer_to_raw_data,
                    mismatch=mismatch,
                )
            )

        return sections

    def validate(self):
        """
        Validate the PE header and sections.
        """
        if not self.pe_header.pe_data:
            raise ValueError("PE header is empty!")
        if len(self.pe_header.pe_data) < PEOffset.IMPORT_TABLE_OFFSET + 4:
            raise ValueError("PE header is too short!")
        return True

    @classmethod
    def from_idb(cls):
        """
        Initialize a PEParser from the current IDA database.
        """
        # Initialize the PE parser
        pe = idautils.peutils_t()
        if not pe:
            raise ValueError("Failed to initialize PE parser")

        return cls(pe_header=PEHeader(pe_data=pe.header()))

    def verify_sections(self):
        """
        Verify that the sections are consistent with the PE header.
        """
        for section in self.get_sections():
            print(
                f"Section: {section.name}, VirtualSize: {section.virtual_size}, "
                f"SizeOfRawData: {section.size_of_raw_data}, File Offset: 0x{section.pointer_to_raw_data:X}"
            )
            if section.mismatch:
                print(f"   >>> {section.mismatch}")
                return False
        return True

    def print_pe_header(self):
        # Print PE Header Info
        print(f"Image Base: 0x{self.pe_header.image_base:X}")
        print(f"BaseOfCode: 0x{self.pe_header.base_of_code:X}")
        print(f"Import Table RVA: 0x{self.pe_header.import_table_rva:X}")
        print(f"Export Table RVA: 0x{self.pe_header.export_table_rva:X}")
        print(f"Resource Table RVA: 0x{self.pe_header.resource_table_rva:X}")
