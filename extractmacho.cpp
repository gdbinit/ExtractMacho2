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
 * extractmacho.cpp
 *
 */

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/queue.h>

#include "extractmacho.hpp"
#include "extractors.h"
#include "validate.h"
#include "logging.h"

#define VERSION "1.0"

uint8_t extract_binary(ea_t address, char *outputFilename);
void add_to_fat_list(ea_t address);
void add_to_hits_list(ea_t address, uint8_t type, uint8_t extracted);
void do_report(void);

enum
{
    k32Bits = 0,
    k64Bits = 1,
    kFAT = 2
};

char *typeArray[] = { "32bits", "64bits", "FAT" };

// structure to add the address of binaries inside fat archives so we don't extract them again
struct fat_list_entry
{
    TAILQ_ENTRY(fat_list_entry) entries;
    ea_t addr; // magic value address
};

TAILQ_HEAD(fat_list_tailq, fat_list_entry);
struct fat_list_tailq fat_list;

struct report_entry
{
    TAILQ_ENTRY(report_entry) entries;
    ea_t addr;
    int type;
    int extracted; // 0 = extracted, 1 = not extracted
};
TAILQ_HEAD(report_tailq, report_entry);

struct report_tailq report_list;

int IDAP_init(void)
{
    msg("----------------------------------\n");
    msg("Extract Mach-O plugin loaded, v%s\n", VERSION);
    msg("(c) fG!, 2019 - reverser@put.as\n");
    msg("----------------------------------\n");
    return PLUGIN_KEEP;
}

void IDAP_term(void)
{
    return;
}

bool IDAP_run(size_t)
{
    // this is useful for testing - plugin will be unloaded after execution
    // so we can copy a new version and call it again using IDC: RunPlugin("extractmacho", -1);
    // this gave (gives?) problems in Windows version
    extern plugin_t PLUGIN;
#ifdef __MAC__
    PLUGIN.flags |= PLUGIN_UNL;
#endif
    TAILQ_INIT(&fat_list);
    TAILQ_INIT(&report_list);
    
    // retrieve current cursor address and it's value
    // so we can verify if it can be a mach-o binary
    ea_t cursorAddress = get_screen_ea();
    uint32 magic = get_dword(cursorAddress);
    
    char *outputFilename = NULL;
    // test if current cursor position has a valid mach-o
    // if yes, ask user if he wants to extract only this one or search for all
    
    if (magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == FAT_CIGAM)
    {
        int answer = ask_yn(0, "Current location contains a potential Mach-O binary! Attempt to extract only this one?");
        // user wants to extract this binary
        if (answer == 1)
        {
            // ask for output location & name
            outputFilename = ask_file(1, NULL, "Select output file...");
            if (outputFilename == NULL || outputFilename[0] == 0)
            {
                return false;
            }
            extract_binary(cursorAddress, outputFilename);
            do_report();
            return true;
        }
        // user cancel
        else if (answer == -1)
        {
            return false;
        }
    }
    
    char form[]="Choose output directory\n<~O~utput directory:F:0:64::>";
    char outputDir[MAXSTR] = {0};
    // user cancel
    if (ask_form(form, outputDir) == 0)
    {
        return false;
    }
    
    // we want to avoid dumping itself so we start at one byte ahead of the first address in the database
    ea_t findAddress = inf.min_ea+1;
    uchar magicFat[] = "\xCA\xFE\xBA\xBE";
    
    // we have a small problem here
    // fat archives contain valid mach-o binaries so they will be found if we search for fat and non-fat binaries
    // solution is to first lookup the fat archives and add the binaries location to a list
    // then match against that list when searching for non-fat binaries and skip extraction if it's on that list
    
    // lookup fat archives
    while (findAddress != BADADDR)
    {
        findAddress = bin_search(findAddress, inf.max_ea, magicFat, NULL, 4, BIN_SEARCH_FORWARD, BIN_SEARCH_NOCASE);
        if (findAddress != BADADDR)
        {
            add_to_fat_list(findAddress);
            char output[MAXSTR];
#ifdef __EA64__
            qsnprintf(output, sizeof(output)-1, "%s/extracted_fat_offset_0x%llx", outputDir, findAddress);
#else
            qsnprintf(output, sizeof(output)-1, "%s/extracted_fat_offset_0x%x", outputDir, findAddress);
#endif
            extract_binary(findAddress, output);
            findAddress += 1;
        }
    }
    
    // reset searching address
    findAddress = inf.min_ea+1;
    
    uchar* archmagic[] = { (uchar*)"\xCE\xFA\xED\xFE", (uchar*)"\xCF\xFA\xED\xFE", (uchar*)"\xFE\xED\xFA\xCE", (uchar*)"\xFE\xED\xFA\xCF" };
    // try to find each type of file all over the IDA database
    for (uint32_t i = 0; i < sizeof(archmagic)/sizeof(*archmagic); i++)
    {
        while (findAddress != BADADDR)
        {
            findAddress = bin_search(findAddress, inf.max_ea, archmagic[i], NULL, 4, BIN_SEARCH_FORWARD, BIN_SEARCH_NOCASE);
            if (findAddress == BADADDR)
            {
                break;
            }
            struct fat_list_entry *tmp_entry = NULL;
            int found = 0;
            TAILQ_FOREACH(tmp_entry, &fat_list, entries)
            {
                if (tmp_entry->addr == findAddress)
                {
                    found = 1;
                    break;
                }
            }
            // not found so extract it
            if (found == 0)
            {
                char output[MAXSTR];
#ifdef __EA64__
                qsnprintf(output, sizeof(output)-1, "%s/extracted_offset_0x%llx", outputDir, findAddress);
#else
                qsnprintf(output, sizeof(output)-1, "%s/extracted_offset_0x%x", outputDir, findAddress);
#endif
                extract_binary(findAddress, output);
                findAddress += 1;
            }
            // we need to advance anyway in case binary is in the fat list
            else
            {
                findAddress += 1;
            }
        }
        // reset searching address
        findAddress = inf.min_ea+1;
    }
    
    // output a final report of what happened
    do_report();
    // cleanup
    struct fat_list_entry *fat_cur, *fat_tmp;
    TAILQ_FOREACH_SAFE(fat_cur, &fat_list, entries, fat_tmp)
    {
        TAILQ_REMOVE(&fat_list, fat_cur, entries);
        qfree(fat_cur);
    }
    struct report_entry *rep_cur, *rep_tmp;
    TAILQ_FOREACH_SAFE(rep_cur, &report_list, entries, rep_tmp)
    {
        TAILQ_REMOVE(&report_list, rep_cur, entries);
        qfree(rep_cur);
    }
    // it's over!
    return true;
}

/*
 * entry function to validate and extract fat and non-fat binaries
 */
uint8_t
extract_binary(ea_t address, char *outputFilename)
{
    uint8_t retValue = 0;
    uint32 magicValue = get_dword(address);
    switch (magicValue)
    {
        case MH_MAGIC:
        case MH_MAGIC_64:
        case MH_CIGAM_64:
        case MH_CIGAM:
        {
            if(validate_macho(address))
            {
                ERROR_MSG("Not a valid mach-o binary at 0x%llx", (uint64_t)address);
                add_to_hits_list(address, (magicValue == MH_MAGIC || magicValue == MH_CIGAM) ? k32Bits : k64Bits, 1);
                return 1;
            }
            // we just need to read mach_header.filetype so no problem in using the 32bit struct
            struct mach_header header = {0};
            get_bytes(&header, sizeof(struct mach_header), address);
            uint32_t filetype = (magicValue == MH_MAGIC || magicValue == MH_MAGIC_64) ? header.filetype : ntohl(header.filetype);
            if (filetype == MH_OBJECT)
            {
                retValue = extract_mhobject(address, outputFilename);
            }
            else
            {
                retValue = extract_macho(address, outputFilename);
            }
            add_to_hits_list(address, (magicValue == MH_MAGIC || magicValue == MH_CIGAM) ? k32Bits : k64Bits, retValue);
            break;
        }
        case FAT_CIGAM:
        {
            retValue = extract_fat(address, outputFilename);
            add_to_hits_list(address, kFAT, retValue);
            break;
        }
        default:
        {
            ERROR_MSG("No valid mach-o binary at current location: 0x%llx", (uint64_t)address);
            retValue = 1;
            break;
        }
    }
    return retValue;
}

/*
 * output final extraction report
 */
void
do_report(void)
{
    OUTPUT_MSG("Mach-O extraction Report:");
    struct report_entry *tmp_entry = NULL;
    TAILQ_FOREACH(tmp_entry, &report_list, entries)
    {
#ifdef __EA64__
        OUTPUT_MSG("Address: 0x%016llx Type: %6s Extracted: %s", tmp_entry->addr, typeArray[tmp_entry->type],
                   tmp_entry->extracted ? "No" : "Yes");
#else
        OUTPUT_MSG("Address: 0x%016x Type: %6s Extracted: %s", tmp_entry->addr, typeArray[tmp_entry->type],
                   tmp_entry->extracted ? "No" : "Yes");
#endif
    }
    OUTPUT_MSG("Mach-O extraction is over!");
}

/*
 * list where we add information for the final report
 */
void
add_to_hits_list(ea_t address, uint8_t type, uint8_t extracted)
{
    struct report_entry *new_entry = (struct report_entry*)qalloc(sizeof(struct report_entry));
    new_entry->addr = address;
    new_entry->type = type;
    new_entry->extracted = extracted;
    TAILQ_INSERT_TAIL(&report_list, new_entry, entries);
}

/*
 * build a list of binaries location inside a fat archive so we don't extract binaries inside fat archives
 * while searching for non-fat binaries
 */
void
add_to_fat_list(ea_t address)
{
    // process the fat structures
    struct fat_header fatHeader = {0};
    get_bytes(&fatHeader, sizeof(struct fat_header), address);
    if (fatHeader.magic == FAT_CIGAM)
    {
        // fat headers are always big endian!
        uint32_t nfat_arch = ntohl(fatHeader.nfat_arch);
        if (nfat_arch > 0)
        {
            // we need to read the fat arch headers to validate
            ea_t archAddress = address + sizeof(struct fat_header);
            for (uint32_t i = 0; i < nfat_arch; i++)
            {
                struct fat_arch fatArch;
                get_bytes(&fatArch, sizeof(struct fat_arch), archAddress);
                // binary is located at start of fat magic plus offset found in the fat_arch structure
                ea_t binLocation = address + ntohl(fatArch.offset);
                
                struct fat_list_entry *new_entry = (struct fat_list_entry*)qalloc(sizeof(struct fat_list_entry));
                new_entry->addr = (uint64_t)binLocation;
                TAILQ_INSERT_TAIL(&fat_list, new_entry, entries);
                archAddress += sizeof(struct fat_arch);
            }
        }
    }
}

char IDAP_comment[] = "Plugin to extract Mach-O binaries from disassembly";
char IDAP_help[] = "Extract Mach-O 2";
char IDAP_name[] = "Extract Mach-O 2";
char IDAP_hotkey[] = "";

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    0,
    IDAP_init,
    IDAP_term,
    IDAP_run,
    IDAP_comment,
    IDAP_help,
    IDAP_name,
    IDAP_hotkey
};
