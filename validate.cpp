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
 * validate.cpp
 *
 */

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/reloc.h>
#include <mach-o/nlist.h>

#include "validate.h"
#include "logging.h"

/*
 * try to validate if a given address contains a valid mach-o file
 */
uint8_t
validate_macho(ea_t address)
{
    DEBUG_MSG("Executing validate macho at address 0x%llx", (uint64_t)address);
    uint32_t magic = get_dword(address);
    
    // default is failure
    uint8_t retvalue = 1;
    if (magic == MH_MAGIC || magic == MH_CIGAM)
    {
        // validate cpu type
        struct mach_header header;
        // retrieve mach_header contents
        if(!get_bytes(&header, sizeof(struct mach_header), address))
        {
            ERROR_MSG("Read bytes failed!");
            return 1;
        }
        // x86 & ARM
        if ((header.cputype == CPU_TYPE_I386 && header.cpusubtype == CPU_SUBTYPE_X86_ALL && magic == MH_MAGIC) ||
            (header.cputype == CPU_TYPE_ARM  && header.cpusubtype == CPU_SUBTYPE_ARM_ALL && magic == MH_MAGIC))
        {
            // validate file type
            switch (header.filetype) {
                case MH_OBJECT:
                case MH_EXECUTE:
                case MH_PRELOAD:
                case MH_DYLIB:
                case MH_DYLINKER:
                case MH_BUNDLE:
                    retvalue = 0;
                    break;                    
                default:
                    break;
            }
        }
        // PowerPC
        else if (ntohl(header.cputype) == CPU_TYPE_POWERPC && magic == MH_CIGAM)
        {
            uint32_t filetype = ntohl(header.filetype);
            switch (filetype) {
                case MH_OBJECT:
                case MH_EXECUTE:
                case MH_PRELOAD:
                case MH_DYLIB:
                case MH_DYLINKER:
                case MH_BUNDLE:
                    retvalue = 0;
                    break;                    
                default:
                    break;
            }
        }
    }
    else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
    {
        // validate cpu type
        struct mach_header_64 header64;
        // retrieve mach_header contents
        if(!get_bytes(&header64, sizeof(struct mach_header_64), address))
        {
            ERROR_MSG("Read bytes failed!");
            return 1;
        }
        // dunno why but some files have cpu sub type ORed with that 0x8000000 value (CPU_SUBTYPE_LIB64)
        if ((header64.cputype == CPU_TYPE_X86_64 && header64.cpusubtype == CPU_SUBTYPE_X86_64_ALL && magic == MH_MAGIC_64) ||
            (header64.cputype == CPU_TYPE_X86_64 && header64.cpusubtype == (CPU_SUBTYPE_X86_64_ALL | 0x80000000) && magic == MH_MAGIC_64))
        {
            // validate file type
            switch (header64.filetype) 
            {
                case MH_OBJECT:
                case MH_EXECUTE:
                case MH_PRELOAD:
                case MH_DYLIB:
                case MH_DYLINKER:
                case MH_BUNDLE:
                case MH_KEXT_BUNDLE:
                    retvalue = 0;
                    break;    
                default:
                    break;
            }
        }
        else if (ntohl(header64.cputype) == CPU_TYPE_POWERPC64 && magic == MH_CIGAM_64)
        {
            uint32_t filetype = ntohl(header64.filetype);
            // validate file type
            switch (filetype) {
                case MH_OBJECT:
                case MH_EXECUTE:
                case MH_PRELOAD:
                case MH_DYLIB:
                case MH_DYLINKER:
                case MH_BUNDLE:
                case MH_KEXT_BUNDLE:
                    retvalue = 0;
                    break;                    
                default:
                    break;
            }
        }
    }
    if (retvalue)
    {
        DEBUG_MSG("validate_macho failed, not a valid binary");
    }
    return retvalue;
}

/*
 * try to validate if a given address contains a valid fat archive
 */
uint8_t 
validate_fat(struct fat_header fatHeader, ea_t position)
{
    // default is failure
    uint8_t retvalue = 1;
    if (fatHeader.magic == FAT_CIGAM)
    {
        // fat headers are always big endian!
        uint32_t nfat_arch = ntohl(fatHeader.nfat_arch);
        if (nfat_arch > 0)
        {
            DEBUG_MSG("nr fat archs %d", ntohl(fatHeader.nfat_arch));
            // we need to read the fat arch headers to validate
            ea_t address = position + sizeof(struct fat_header);
            for (uint32_t i = 0; i < nfat_arch; i++)
            {
                struct fat_arch fatArch;
                get_bytes(&fatArch, sizeof(struct fat_arch), address);
                uint32_t cputype = ntohl(fatArch.cputype);
                uint32_t cpusubtype = ntohl(fatArch.cpusubtype);
                // validate cpu type & subtype, hopefully false positives rate is extremely low
                switch (cputype) 
                {
                    case CPU_TYPE_X86:
                    case CPU_TYPE_X86_64:
                    case CPU_TYPE_POWERPC:
                    case CPU_TYPE_POWERPC64:
                    case CPU_TYPE_ARM:
                    {
                        switch (cpusubtype) 
                        {
                            case CPU_SUBTYPE_X86_ALL: 
                            case CPU_SUBTYPE_POWERPC_ALL: // the X86_64 and ARM are equal to these two
                            case (CPU_SUBTYPE_X86_64_ALL | 0x80000000):
                                retvalue = 0;
                                break;
                        }
                        break;
                    }
                }
                address += sizeof(struct fat_arch);
            }
        }
    }
    DEBUG_MSG("validate_fat ret %d", retvalue);
    return retvalue;
}
