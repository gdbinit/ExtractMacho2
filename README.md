Extract Mach-O 2
v1.0
(c) 2019, fG! - reverser@put.as - https://reverse.put.as

This is a very simple IDA plugin to extract all Mach-O binaries contained anywhere in the disassembly.

It supports 32 and 64bits binaries, and also fat binaries, Intel, PPC and ARM!

The default behavior is to search all the IDA database for Mach-O binaries.

If you position the cursor at a Mach-O binary start address (Mach-O magic values 0xFEEDFACE or 0xFEEDFACF),
it will ask if you want to dump that specific binary. If you say no, it will fallback to default behavior.

Only macOS support on this version. Tested with IDA 7.2.

To compile for OS X use the XCode Project.

You might need to edit the XCode project and set the paths to the IDA SDK.

No default shortcut is set. 
Edit IDAP_hotkey at extractmacho.cpp to your own preference if you wish so.

Bug reports, fixes and patches are welcome: reverser@put.as or github.com/gdbinit/ExtractMacho2

That's it! Enjoy :-)

fG!

v1.0 - Initial refactoring of older Extract Mach-O plugin
