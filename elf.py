import struct
import sys

class Ehdr():
    fmt = '<16B2HI3QI6H'
    def __init__(self, e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx):
        self.e_ident        = e_ident
        self.e_type         = e_type
        self.e_machine      = e_machine
        self.e_version      = e_version
        self.e_entry        = e_entry
        self.e_phoff        = e_phoff
        self.e_shoff        = e_shoff
        self.e_flags        = e_flags
        self.e_ehsize       = e_ehsize
        self.e_phentsize    = e_phentsize
        self.e_phnum        = e_phnum
        self.e_shentsize    = e_shentsize
        self.e_shnum        = e_shnum
        self.e_shstrndx     = e_shstrndx

    def get_raw_header(self):
        buf = b''
        for byte in self.e_ident:
            buf += struct.pack('B', byte)

        buf +=  struct.pack('H', self.e_type     )
        buf +=  struct.pack('H', self.e_machine  )
        buf +=  struct.pack('I', self.e_version  )
        buf +=  struct.pack('Q', self.e_entry    )
        buf +=  struct.pack('Q', self.e_phoff    )
        buf +=  struct.pack('Q', self.e_shoff    )
        buf +=  struct.pack('I', self.e_flags    )
        buf +=  struct.pack('H', self.e_ehsize   )
        buf +=  struct.pack('H', self.e_phentsize)
        buf +=  struct.pack('H', self.e_phnum    )
        buf +=  struct.pack('H', self.e_shentsize)
        buf +=  struct.pack('H', self.e_shnum    )
        buf +=  struct.pack('H', self.e_shstrndx )

        return buf

    def dump(self):
        print('-------elf header-----------')
        print(' e_ident    {}'.format(self.e_ident))    
        print(' e_type     {}'.format(self.e_type))   
        print(' e_machine  {}'.format(self.e_machine))  
        print(' e_version  {}'.format(self.e_version))
        print(' e_entry    {}'.format(hex(self.e_entry))) 
        print(' e_phoff    {}'.format(self.e_phoff))
        print(' e_shoff    {}'.format(self.e_shoff))
        print(' e_flags    {}'.format(self.e_flags))
        print(' e_ehsize   {}'.format(self.e_ehsize))
        print(' e_phentsize{}'.format(self.e_phentsize))
        print(' e_phnum    {}'.format(self.e_phnum))
        print(' e_shentsize{}'.format(self.e_shentsize))
        print(' e_shnum    {}'.format(self.e_shnum))
        print(' e_shstrndx {}'.format(self.e_shstrndx))


class Phdr():
    fmt = '<IIQQQQQQ'
    def __init__(self, p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align):
        self.p_type     = p_type
        self.p_flags    = p_flags
        self.p_offset   = p_offset
        self.p_vaddr    = p_vaddr
        self.p_paddr    = p_paddr
        self.p_filesz   = p_filesz
        self.p_memsz    = p_memsz
        self.p_align    = p_align
    
    def get_raw_header(self):
        buf = b''

        buf += struct.pack('I', self.p_type  )
        buf += struct.pack('I', self.p_flags )
        buf += struct.pack('Q', self.p_offset)
        buf += struct.pack('Q', self.p_vaddr )
        buf += struct.pack('Q', self.p_paddr )
        buf += struct.pack('Q', self.p_filesz)
        buf += struct.pack('Q', self.p_memsz )
        buf += struct.pack('Q', self.p_align )

        return buf

    def dump(self):
        print("-----------program header----------------")
        print(' p_type   {}'.format( self.p_type  ))
        print(' p_flags  {}'.format( self.p_flags ))
        print(' p_offset {}'.format( self.p_offset))
        print(' p_vaddr  {}'.format( self.p_vaddr ))
        print(' p_paddr  {}'.format( self.p_paddr ))
        print(' p_filesz {}'.format( self.p_filesz))
        print(' p_memsz  {}'.format( self.p_memsz ))
        print(' p_align  {}'.format( self.p_align ))

class Shdr():
    fmt = '<IIQQQQIIQQ'
    def __init__(self, sh_name_raw, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
        self.sh_name_raw    = sh_name_raw
        self.sh_name        = sh_name
        self.sh_type        = sh_type
        self.sh_flags       = sh_flags
        self.sh_addr        = sh_addr
        self.sh_offset      = sh_offset
        self.sh_size        = sh_size
        self.sh_link        = sh_link
        self.sh_info        = sh_info
        self.sh_addralign   = sh_addralign
        self.sh_entsize     = sh_entsize

    def get_raw_header(self):
        buf = b''
        buf += struct.pack('I', self.sh_name_raw)
        buf += struct.pack('I', self.sh_type     )
        buf += struct.pack('Q', self.sh_flags    )
        buf += struct.pack('Q', self.sh_addr     )
        buf += struct.pack('Q', self.sh_offset   )
        buf += struct.pack('Q', self.sh_size     )
        buf += struct.pack('I', self.sh_link     )
        buf += struct.pack('I', self.sh_info     )
        buf += struct.pack('Q', self.sh_addralign)
        buf += struct.pack('Q', self.sh_entsize  )

        return buf

    def dump(self):
        print("-----------section header----------------")
        print(" sh_name     {}".format( self.sh_name     ))
        print(" sh_type     {}".format( self.sh_type     ))
        print(" sh_flags    {}".format( self.sh_flags    ))
        print(" sh_addr     {}".format( hex(self.sh_addr)     ))
        print(" sh_offset   {}".format( self.sh_offset   ))
        print(" sh_size     {}".format( self.sh_size     ))
        print(" sh_link     {}".format( self.sh_link     ))
        print(" sh_info     {}".format( self.sh_info     ))
        print(" sh_addralig {}".format( self.sh_addralign))
        print(" sh_entsize  {}".format( self.sh_entsize  ))

class Elf():
    def __init__(self):
        self.section_headers = []
        self.program_headers = []
        self.sections = []
    
    def read_file(self, path):
        with open(path, 'rb') as f:
            elf_file = f.read()
        
        self.elf_header = self.get_elf_header(elf_file)
        self.program_headers = self.get_program_headers(elf_file)
        self.section_headers = self.get_section_headers(elf_file)
        self.get_sections(elf_file)

    def write_file(self, path):
        f = open(path, 'wb')
        buf = self.elf_header.get_raw_header()
        f.write(buf)

        f.seek(self.elf_header.e_phoff)
        for phdr in self.program_headers:
            p = phdr.get_raw_header()
            f.write(p)
        
        f.seek(self.elf_header.e_shoff)
        for shdr in self.section_headers:
            s = shdr.get_raw_header()
            f.write(s)
        
        for data,shdr in zip(self.sections, self.section_headers):
            f.seek(shdr.sh_offset)
            f.write(data)
        
        f.close()
    
    def add_section(self, data, name):
        self.elf_header.e_shnum += 1
        self.sections.append(data)
        # 値を設定できるようにする
        sh_type     = 1
        sh_flags    = 6
        sh_offset   = self.elf_header.e_shoff
        sh_addr     = 0x400000 + sh_offset
        sh_size     = len(data)
        sh_link     = 0
        sh_info     = 0
        sh_addralign = 0
        sh_entsize  = 0 

        self.section_headers.append(Shdr(self.section_headers[self.elf_header.e_shstrndx].sh_size, name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize))

        self.elf_header.e_shoff += sh_size

        # change the name
        self.sections[self.elf_header.e_shstrndx] += name.encode() + b'\0'
        self.section_headers[self.elf_header.e_shstrndx].sh_size += len(name)
        #self.section_headers[self.elf_header.e_shstrndx].sh_offset += len(name)
        for shdr in self.section_headers:
            if shdr.sh_offset > self.section_headers[self.elf_header.e_shstrndx].sh_offset:
                if shdr.sh_addr != 0:
                    shdr.sh_addr += len(name)
                shdr.sh_offset += len(name)

        self.elf_header.e_shoff += len(name)


    def delete_section(self):
        pass

    def dump_headers(self):
        self.elf_header.dump()
        print()
        print()
        print()
        print()
        for phdr in elf.program_headers:
            phdr.dump()
        print()
        print()
        print()
        print()
        for shdr in elf.section_headers:
            shdr.dump()

    def get_elf_header(self, elf_file):
        raw_ehdr = list(struct.unpack_from(Ehdr.fmt, elf_file, 0))
        # set elf header
        e_ident     = raw_ehdr[0:16]
        e_type      = raw_ehdr[16]
        e_machine   = raw_ehdr[17]
        e_version   = raw_ehdr[18]
        e_entry     = raw_ehdr[19]
        e_phoff     = raw_ehdr[20]
        e_shoff     = raw_ehdr[21]
        e_flags     = raw_ehdr[22]
        e_ehsize    = raw_ehdr[23]
        e_phentsize = raw_ehdr[24]
        e_phnum     = raw_ehdr[25]
        e_shentsize = raw_ehdr[26]
        e_shnum     = raw_ehdr[27]
        e_shstrndx  = raw_ehdr[28]

        return Ehdr(e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)

    def get_program_headers(self, elf_file):
        phdrs = []
        for i in range(self.elf_header.e_phnum):
            raw_phdr = struct.unpack_from(Phdr.fmt, elf_file, self.elf_header.e_phoff+(i * self.elf_header.e_phentsize))

            p_type     = raw_phdr[0]
            p_flags    = raw_phdr[1]
            p_offset   = raw_phdr[2]
            p_vaddr    = raw_phdr[3]
            p_paddr    = raw_phdr[4]
            p_filesz   = raw_phdr[5]
            p_memsz    = raw_phdr[6]
            p_align    = raw_phdr[7]

            phdrs.append(Phdr(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align))
        
        return phdrs

    def get_section_headers(self, elf_file):
        shdrs = []
        shdr_names_index = []

        for i in range(self.elf_header.e_shnum):
            raw_shdr = struct.unpack_from(Shdr.fmt, elf_file, self.elf_header.e_shoff+(i * self.elf_header.e_shentsize))
            
            shdr_names_index.append(raw_shdr[0])
            sh_name_raw    = raw_shdr[0]
            sh_name        = ''
            sh_type        = raw_shdr[1]
            sh_flags       = raw_shdr[2]
            sh_addr        = raw_shdr[3]
            sh_offset      = raw_shdr[4]
            sh_size        = raw_shdr[5]
            sh_link        = raw_shdr[6]
            sh_info        = raw_shdr[7]
            sh_addralign   = raw_shdr[8]
            sh_entsize     = raw_shdr[9]

            shdrs.append(Shdr(sh_name_raw, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize))

        str_table_section_offset = shdrs[self.elf_header.e_shstrndx].sh_offset
        sh_name_bin = elf_file[str_table_section_offset : str_table_section_offset + shdrs[self.elf_header.e_shstrndx].sh_size]
        for i in range(self.elf_header.e_shnum):
            sh_name_str = ''
            for c in sh_name_bin[shdr_names_index[i]:]:
                if chr(c) == '\0':
                    break
                sh_name_str += chr(c)
            shdrs[i].sh_name = sh_name_str

        return shdrs
    
    def get_sections(self,elf_file):
        for shdr in self.section_headers:
            raw_section = bytes(struct.unpack_from('B' * shdr.sh_size, elf_file, shdr.sh_offset))
            self.sections.append(raw_section)


if __name__ == '__main__':
    path = sys.argv[1]
    elf = Elf()
    elf.read_file(path)
    
    elf.add_section(b'AAAA', '.hoge')
    elf.write_file('b.out')
    #elf.dump_headers()
