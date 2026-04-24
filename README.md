# Free Pascal port of LZ5/LIZARD compressor decompressor (.lz5 / .liz)

License: BSD-2

# Usage

Add LizSimple.pas to your uses.

```
function LZ5CompressStreams (Infile, Outfile: TStream): Integer;
function LZ5DecompressStreams(Infile, Outfile: TStream): Integer;

function LZ5CompressFile(const Infilename, Outfilename: String): Integer;
function LZ5DecompressFile(const Infilename, Outfilename: String): Integer;

function LZ5(Uncompressed: AnsiString): AnsiString;
function UnLZ5(Compressed: AnsiString): AnsiString;


function LIZCompressStreams (Infile, Outfile: TStream): Integer;
function LIZDecompressStreams(Infile, Outfile: TStream): Integer;

function LIZCompressFile(const Infilename, Outfilename: String): Integer;
function LIZDecompressFile(const Infilename, Outfilename: String): Integer;

function LIZ(Uncompressed: AnsiString): AnsiString;
function UnLIZ(Compressed: AnsiString): AnsiString;
```
