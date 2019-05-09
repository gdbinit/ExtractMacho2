/*
 * ___________         __                        __
 * \_   _____/__  ____/  |_____________    _____/  |_
 *   |    __)_\  \/  /\   __\_  __ \__  \ _/ ___\   __\
 *   |        \>    <  |  |  |  | \// __ \\  \___|  |
 *  /_______  /__/\_ \ |__|  |__|  (____  /\___  >__|
 *          \/      \/                  \/     \/
 *    _____                .__              ________      ___
 *   /     \ _____    ____ |  |__           \_____  \    |_  |
 *  /  \ /  \\__  \ _/ ___\|  |  \   ______  /   |   \   |  _|
 * /    Y    \/ __ \\  \___|   Y  \ /_____/ /    |    \  |___|
 * \____|__  (____  /\___  >___|  /         \_______  /
 *         \/     \/     \/     \/                  \/
 *
 * Extract Mach-O 2 - v1.0
 * (c) 2019, fG! - reverser@put.as - https://reverse.put.as
 *
 * An IDA plugin to extract Mach-O binaries inside code or data segments
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * extractors.cpp
 *
 */

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/reloc.h>
#include <mach-o/nlist.h>

#include "extractors.h"
#include "validate.h"
#include "logging.h"

#define bswap64(y) (((uint64_t)ntohl(y)) << 32 | ntohl(y>>32))

uint8_t
extract_mhobject(ea_t address, char *outputFilename)
{
    uint32 magic = get_dword(address);
    
    struct mach_header_64 *mach_header = NULL;
    
    if (magic == MH_MAGIC)
    {
        DEBUG_MSG("Target is 32bits!");
        mach_header = (struct mach_header_64 *)qalloc(sizeof(struct mach_header_64));
        // retrieve mach_header contents
        if(!get_bytes(mach_header, sizeof(struct mach_header), address))
        {
            ERROR_MSG("Read bytes failed!");
            qfree(mach_header);
            return 1;
        }
    }
    else if (magic == MH_MAGIC_64)
    {
        DEBUG_MSG("Target is 64bits!");
        mach_header = (struct mach_header_64 *)qalloc(sizeof(struct mach_header_64));
        if(!get_bytes(mach_header, sizeof(struct mach_header_64), address))
        {
            ERROR_MSG("Read bytes failed!");
            qfree(mach_header);
            return 1;
        }
    }
    else
    {
        return 1;
    }
    
    // open output file
    FILE *outputFile = qfopen(outputFilename, "wb+");
    if (outputFile == NULL)
    {
        ERROR_MSG("Could not open %s file!", outputFilename);
        qfree(mach_header);
        return 1;
    }
    
    /*
     * we need to write 3 distinct blocks of data:
     * 1) the mach_header
     * 2) the load commands
     * 3) the code and data from the LC_SEGMENT/LC_SEGMENT_64 commands
     */
    
    // write the mach_header to the file
    if (magic == MH_MAGIC_64)
    {
        qfwrite(outputFile, mach_header, sizeof(struct mach_header_64));
    }
    else
    {
        qfwrite(outputFile, mach_header, sizeof(struct mach_header));
    }
    
    // swap the endianness of some fields if it's powerpc target
    if (magic == MH_CIGAM)
    {
        mach_header->ncmds = ntohl(mach_header->ncmds);
        mach_header->sizeofcmds = ntohl(mach_header->sizeofcmds);
    }
    else if (magic == MH_CIGAM_64)
    {
        mach_header->ncmds = ntohl(mach_header->ncmds);
        mach_header->sizeofcmds = ntohl(mach_header->sizeofcmds);
    }

    // read the load commands
    uint32_t ncmds = mach_header->ncmds;
    uint32_t sizeofcmds = mach_header->sizeofcmds;
    uint32_t headerSize = sizeof(struct mach_header_64);
    if (magic == MH_MAGIC)
    {
        headerSize = sizeof(struct mach_header);
    }
    
    uint8_t *loadcmdsBuffer = (uint8_t*)qalloc(sizeofcmds);
    get_bytes(loadcmdsBuffer, sizeofcmds, address + headerSize);
    // write all the load commands block to the output file
    // only LC_SEGMENT commands contain further data
    qfwrite(outputFile, loadcmdsBuffer, sizeofcmds);
    
    // and now process the load commands so we can retrieve code and data
    struct load_command loadCommand;
    ea_t cmdsBaseAddress = address + headerSize;    
    
    // read segments so we can write the code and data
    // only the segment commands have useful information
    for (uint32_t i = 0; i < ncmds; i++)
    {
        get_bytes(&loadCommand, sizeof(struct load_command), cmdsBaseAddress);
        struct segment_command segmentCommand;
        struct segment_command_64 segmentCommand64;
        // swap the endianness of some fields if it's powerpc target
        if (magic == MH_CIGAM || magic == MH_CIGAM_64)
        {
            loadCommand.cmd = ntohl(loadCommand.cmd);
            loadCommand.cmdsize = ntohl(loadCommand.cmdsize);
        }

        // 32bits targets
        if (loadCommand.cmd == LC_SEGMENT)
        {
            get_bytes(&segmentCommand, sizeof(struct segment_command), cmdsBaseAddress);
            // swap the endianness of some fields if it's powerpc target
            if (magic == MH_CIGAM)
            {
                segmentCommand.nsects   = ntohl(segmentCommand.nsects);
                segmentCommand.fileoff  = ntohl(segmentCommand.fileoff);
                segmentCommand.filesize = ntohl(segmentCommand.filesize);
            }

            ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command);
            struct section sectionCommand; 
            // iterate thru all sections to find the first code offset
            // FIXME: we need to find the lowest one since the section info can be reordered
            for (uint32_t x = 0; x < segmentCommand.nsects; x++)
            {
                get_bytes(&sectionCommand, sizeof(struct section), sectionAddress);
                // swap the endianness of some fields if it's powerpc target
                if (magic == MH_CIGAM)
                {
                    sectionCommand.offset = ntohl(sectionCommand.offset);
                    sectionCommand.nreloc = ntohl(sectionCommand.nreloc);
                    sectionCommand.reloff = ntohl(sectionCommand.reloff);
                }
                if (sectionCommand.nreloc > 0)
                {
                    uint32_t size = sectionCommand.nreloc*sizeof(struct relocation_info);
                    uint8_t *relocBuf = (uint8_t*)qalloc(size);
                    get_bytes(relocBuf, size, address + sectionCommand.reloff);
                    qfseek(outputFile, sectionCommand.reloff, SEEK_SET);
                    qfwrite(outputFile, relocBuf, size);
                    qfree(relocBuf);
                }
                sectionAddress += sizeof(struct section);
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand.filesize);
            get_bytes(buf, segmentCommand.filesize, address + segmentCommand.fileoff);
            // always set the offset
            qfseek(outputFile, segmentCommand.fileoff, SEEK_SET);
            qfwrite(outputFile, buf, segmentCommand.filesize);
            qfree(buf);
        }
        // we need this to dump missing relocations
        else if (loadCommand.cmd == LC_SYMTAB)
        {
            struct symtab_command symtabCommand;
            get_bytes(&symtabCommand, sizeof(struct symtab_command), cmdsBaseAddress);
            // swap the endianness of some fields if it's powerpc target
            if (magic == MH_CIGAM || magic == MH_CIGAM_64)
            {
                symtabCommand.nsyms   = ntohl(symtabCommand.nsyms);
                symtabCommand.symoff  = ntohl(symtabCommand.symoff);
                symtabCommand.stroff  = ntohl(symtabCommand.stroff);
                symtabCommand.strsize = ntohl(symtabCommand.strsize);
            }
            
            if (symtabCommand.symoff > 0)
            {
                void *buf = qalloc(symtabCommand.nsyms*sizeof(struct nlist));
                get_bytes(buf, symtabCommand.nsyms*sizeof(struct nlist), address + symtabCommand.symoff);
                qfseek(outputFile, symtabCommand.symoff, SEEK_SET);
                qfwrite(outputFile, buf, symtabCommand.nsyms*sizeof(struct nlist));
                qfree(buf);
            }
            if (symtabCommand.stroff > 0)
            {
                void *buf = qalloc(symtabCommand.strsize);
                get_bytes(buf, symtabCommand.strsize, address + symtabCommand.stroff);
                qfseek(outputFile, symtabCommand.stroff, SEEK_SET);
                qfwrite(outputFile, buf, symtabCommand.strsize);
                qfree(buf);
            }
        }
        // 64bits targets
        // FIXME: will this work ? needs to be tested :-)
        else if (loadCommand.cmd == LC_SEGMENT_64)
        {
            get_bytes(&segmentCommand64, sizeof(struct segment_command_64), cmdsBaseAddress);
            // swap the endianness of some fields if it's powerpc target
            if (magic == MH_CIGAM_64)
            {
                segmentCommand64.nsects   = ntohl(segmentCommand64.nsects);
                segmentCommand64.fileoff  = bswap64(segmentCommand64.fileoff);
                segmentCommand64.filesize = bswap64(segmentCommand64.filesize);
            }

            ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command_64);
            struct section_64 sectionCommand64;
            for (uint32_t x = 0; x < segmentCommand64.nsects; x++)
            {
                get_bytes(&sectionCommand64, sizeof(struct section_64), sectionAddress);
                // swap the endianness of some fields if it's powerpc target
                if (magic == MH_CIGAM_64)
                {
                    sectionCommand64.offset = ntohl(sectionCommand64.offset);
                    sectionCommand64.nreloc = ntohl(sectionCommand64.nreloc);
                    sectionCommand64.reloff = ntohl(sectionCommand64.reloff);
                }
                
                if (sectionCommand64.nreloc > 0)
                {
                    uint32_t size = sectionCommand64.nreloc*sizeof(struct relocation_info);
                    uint8_t *relocBuf = (uint8_t*)qalloc(size);
                    get_bytes(relocBuf, size, address + sectionCommand64.reloff);
                    qfseek(outputFile, sectionCommand64.reloff, SEEK_SET);
                    qfwrite(outputFile, relocBuf, size);
                    qfree(relocBuf);
                }
                sectionAddress += sizeof(struct section_64);
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand64.filesize);
            get_bytes(buf, segmentCommand64.filesize, address + segmentCommand64.fileoff);
            qfseek(outputFile, segmentCommand64.fileoff, SEEK_SET);
            qfwrite(outputFile, buf, segmentCommand64.filesize);
            qfree(buf);
        }
        cmdsBaseAddress += loadCommand.cmdsize;
    }
    
    // all done, close file and free remaining buffers!
    qfclose(outputFile);
    qfree(mach_header);
    qfree(loadcmdsBuffer);
    return 0;
    
}

/*
 * function to extract non-fat binaries, 32 and 64bits
 */
uint8_t 
extract_macho(ea_t address, char *outputFilename)
{
    uint32 magic = get_dword(address);
    
    struct mach_header_64 *mach_header = NULL;
    
    if (magic == MH_MAGIC || magic == MH_CIGAM)
    {
        DEBUG_MSG("Target is 32bits!");
        mach_header = (struct mach_header_64 *)qalloc(sizeof(struct mach_header));
        // retrieve mach_header contents
        if(!get_bytes(mach_header, sizeof(struct mach_header), address))
        {
            ERROR_MSG("Read bytes failed!");
            qfree(mach_header);
            return 1;
        }
    }
    else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
    {
        DEBUG_MSG("Target is 64bits!");
        mach_header = (struct mach_header_64 *)qalloc(sizeof(struct mach_header_64));
        if(!get_bytes(mach_header, sizeof(struct mach_header_64), address))
        {
            ERROR_MSG("Read bytes failed!");
            qfree(mach_header);
            return 1;
        }
    }
    else
    {
        ERROR_MSG("Unknown target!");
        return 1;
    }
    
    // open output file
    FILE *outputFile = qfopen(outputFilename, "wb+");
    if (outputFile == NULL)
    {
        ERROR_MSG("Could not open %s file!", outputFilename);
        qfree(mach_header);
        return 1;
    }
    
    /*
     * we need to write 3 distinct blocks of data:
     * 1) the mach_header
     * 2) the load commands
     * 3) the code and data from the LC_SEGMENT/LC_SEGMENT_64 commands
     */
    
    // write the mach_header to the file
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
    {
        qfwrite(outputFile, mach_header, sizeof(struct mach_header_64));
    }
    else
    {
        qfwrite(outputFile, mach_header, sizeof(struct mach_header));
    }
    // swap the endianness of some fields if it's powerpc target
    if (magic == MH_CIGAM)
    {
        mach_header->ncmds = ntohl(mach_header->ncmds);
        mach_header->sizeofcmds = ntohl(mach_header->sizeofcmds);
    }
    else if (magic == MH_CIGAM_64)
    {
        mach_header->ncmds = ntohl(mach_header->ncmds);
        mach_header->sizeofcmds = ntohl(mach_header->sizeofcmds);
    }
    
    // read the load commands
    uint32_t ncmds      = mach_header->ncmds;
    uint32_t sizeofcmds = mach_header->sizeofcmds;
    uint32_t headerSize = sizeof(struct mach_header_64);
    if (magic == MH_MAGIC || magic == MH_CIGAM)
    {
        headerSize = sizeof(struct mach_header);
    }
    
    uint8_t *loadcmdsBuffer = (uint8_t*)qalloc(sizeofcmds);
    get_bytes(loadcmdsBuffer, sizeofcmds, address + headerSize);
    // write all the load commands block to the output file
    // only LC_SEGMENT commands contain further data
    qfwrite(outputFile, loadcmdsBuffer, sizeofcmds);
    
    // and now process the load commands so we can retrieve code and data
    struct load_command loadCommand;
    ea_t cmdsBaseAddress = address + headerSize;    
    ea_t codeOffset = 0;
    
    // read segments so we can write the code and data
    // only the segment commands have useful information
    for (uint32_t i = 0; i < ncmds; i++)
    {
        get_bytes(&loadCommand, sizeof(struct load_command), cmdsBaseAddress);
        struct segment_command segmentCommand;
        struct segment_command_64 segmentCommand64;
        // swap the endianness of some fields if it's powerpc target
        if (magic == MH_CIGAM || magic == MH_CIGAM_64)
        {
            loadCommand.cmd     = ntohl(loadCommand.cmd);
            loadCommand.cmdsize = ntohl(loadCommand.cmdsize);
        }
        
        // 32bits targets
        // FIXME: do we also need to dump the relocs info here ?
        if (loadCommand.cmd == LC_SEGMENT)
        {
            get_bytes(&segmentCommand, sizeof(struct segment_command), cmdsBaseAddress);
            // swap the endianness of some fields if it's powerpc target
            if (magic == MH_CIGAM)
            {
                segmentCommand.nsects   = ntohl(segmentCommand.nsects);
                segmentCommand.fileoff  = ntohl(segmentCommand.fileoff);
                segmentCommand.filesize = ntohl(segmentCommand.filesize);
            }
            // the file offset info in LC_SEGMENT is zero at __TEXT so we need to get it from the sections
            // the size is ok to be used
            if (strncmp(segmentCommand.segname, "__TEXT", 16) == 0)
            {
                ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command);
                struct section sectionCommand; 
                // iterate thru all sections to find the first code offset
                // FIXME: we need to find the lowest one since the section info can be reordered
                for (uint32_t x = 0; x < segmentCommand.nsects; x++)
                {
                    get_bytes(&sectionCommand, sizeof(struct section), sectionAddress);
                    // swap the endianness of some fields if it's powerpc target
                    if (magic == MH_CIGAM)
                    {
                        sectionCommand.offset = ntohl(sectionCommand.offset);
                    }
                    
                    if (strncmp(sectionCommand.sectname, "__text", 16) == 0)
                    {
                        codeOffset = sectionCommand.offset;
                        break;
                    }
                    sectionAddress += sizeof(struct section);
                }
            }
            // for all other segments the fileoffset info in the LC_SEGMENT is valid so we can use it
            else
            {
                codeOffset = segmentCommand.fileoff;
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand.filesize);
            get_bytes(buf, segmentCommand.filesize, address + codeOffset);
            // always set the offset
            qfseek(outputFile, codeOffset, SEEK_SET);
            qfwrite(outputFile, buf, segmentCommand.filesize);
            qfree(buf);
        }
        // 64bits targets
        else if (loadCommand.cmd == LC_SEGMENT_64)
        {
            get_bytes(&segmentCommand64, sizeof(struct segment_command_64), cmdsBaseAddress);
            // swap the endianness of some fields if it's powerpc target
            if (magic == MH_CIGAM_64)
            {
                segmentCommand64.nsects   = ntohl(segmentCommand64.nsects);
                segmentCommand64.fileoff  = bswap64(segmentCommand64.fileoff);
                segmentCommand64.filesize = bswap64(segmentCommand64.filesize);
            }

            if(strncmp(segmentCommand64.segname, "__TEXT", 16) == 0)
            {
                ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command_64);
                struct section_64 sectionCommand64;
                for (uint32_t x = 0; x < segmentCommand64.nsects; x++)
                {
                    get_bytes(&sectionCommand64, sizeof(struct section_64), sectionAddress);
                    // swap the endianness of some fields if it's powerpc target
                    if (magic == MH_CIGAM_64)
                    {
                        sectionCommand64.offset = ntohl(sectionCommand64.offset);
                    }
                    if (strncmp(sectionCommand64.sectname, "__text", 16) == 0)
                    {
                        codeOffset = sectionCommand64.offset;
                        break;
                    }
                    sectionAddress += sizeof(struct section_64);
                }
            }
            else
            {
                codeOffset = segmentCommand64.fileoff;
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand64.filesize);
            get_bytes(buf, segmentCommand64.filesize, address + codeOffset);
            qfseek(outputFile, codeOffset, SEEK_SET);
            qfwrite(outputFile, buf, segmentCommand64.filesize);
            qfree(buf);
        }
        cmdsBaseAddress += loadCommand.cmdsize;
    }
    
    // all done, close file and free remaining buffers!
    qfclose(outputFile);
    qfree(mach_header);
    qfree(loadcmdsBuffer);
    return 0;
}

/*
 * function to extract fat archives
 */
uint8_t 
extract_fat(ea_t address, char *outputFilename)
{
    DEBUG_MSG("Trying to extract a fat binary target!");
    struct fat_header fatHeader = {0};
    if(!get_bytes(&fatHeader, sizeof(struct fat_header), address))
    {
        ERROR_MSG("Read bytes failed!");
        return 1;
    }
    if(validate_fat(fatHeader, address))
    {
        return 1;
    }
    // for fat binaries things are much easier to dump
    // since the fat_arch struct contains total size of the binary :-)
    // open output file
    FILE *outputFile = qfopen(outputFilename, "wb+");
    if (outputFile == NULL)
    {
        ERROR_MSG("Could not open %s file!", outputFilename);
        return 1;
    }
    // write fat_header
    qfwrite(outputFile, &fatHeader, sizeof(struct fat_header));
    // read fat_arch
    ea_t fatArchAddress = address + sizeof(struct fat_header);
    uint32_t fatArchSize = sizeof(struct fat_arch)*ntohl(fatHeader.nfat_arch);
    // write all fat_arch structs
    void *fatArchBuf = qalloc(fatArchSize);
    if(!get_bytes(fatArchBuf, fatArchSize, fatArchAddress))
    {
        ERROR_MSG("Read bytes failed!");
        qfree(fatArchBuf);
        return 1;
    }
    qfwrite(outputFile, fatArchBuf, fatArchSize);
    qfree(fatArchBuf);
    // write the mach-o binaries inside the fat archive
    for (uint32_t i = 0; i < ntohl(fatHeader.nfat_arch) ; i++)
    {
        struct fat_arch tempFatArch;
        // read the fat_arch struct
        if(!get_bytes(&tempFatArch, sizeof(struct fat_arch), fatArchAddress))
        {
            ERROR_MSG("Read bytes failed!");
            return 1;
        }
        // read and write the mach-o binary pointed by each fat_arch struct
        void *tempBuf = qalloc(ntohl(tempFatArch.size));
        if(!get_bytes(tempBuf, ntohl(tempFatArch.size), address+ntohl(tempFatArch.offset)))
        {
            ERROR_MSG("Read bytes failed!");
            qfree(tempBuf);
            return 1;
        }
        qfseek(outputFile, ntohl(tempFatArch.offset), SEEK_SET);
        qfwrite(outputFile, tempBuf, ntohl(tempFatArch.size));
        qfree(tempBuf);
        // advance to next fat_arch struct
        fatArchAddress += sizeof(struct fat_arch);
    }
    // all done
    qfclose(outputFile);
    return 0;
}
