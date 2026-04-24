unit LizSimple;

//  Stream-based Lizard/LZ5 frame compress / decompress.
//
//  LZ5CompressStreams   – level 10, fastLZ4   (fastest, LZ4-compatible tokens)
//  LIZCompressStreams   – level 20, fastLIZv1  (better ratio, LIZv1 tokens)
//  LZ5DecompressStreams – decodes any Lizard frame (magic $184D2206)
//  LIZDecompressStreams – same as above (frame format is shared)
//
//  Return value: bytes written to Outfile, or -1 on error.
//
//  Both compressors write a valid Lizard frame:
//    magic(4) + FLG(1) + BD(1) + HC(1)          = 7-byte header
//    [block-header(4) + block-data] × N           = compressed blocks
//    end-mark(4)                                  = 4 zero bytes


{$mode objfpc}{$H+}
{$pointermath on}
{$Q-}{$R-}

interface

uses SysUtils, lz5, xxHash, Classes;

function LZ5CompressStreams (Infile, Outfile: TStream): Integer;
function LZ5DecompressStreams(Infile, Outfile: TStream): Integer;

function LZ5CompressFile(const Infilename, Outfilename: String): Integer;
function LZ5DecompressFile(const Infilename, Outfilename: String): Integer;

function LZ5(Uncompressed: AnsiString): AnsiString;
function UnLZ5(Compressed: AnsiString): AnsiString;


function LIZCompressStreams (Infile, Outfile: TStream): Integer;
function LIZDecompressStreams(Infile, Outfile: TStream): Integer;

function LIZCompressFile(const Infilename, Outfilename: String): Integer;
function LIZDecompressFileconst (Infilename, Outfilename: String): Integer;

function LIZ(Uncompressed: AnsiString): AnsiString;
function UnLIZ(Compressed: AnsiString): AnsiString;

implementation

// ===================================================================
//  Constants
//  =================================================================== 

const
  LIZARDF_MAGIC           = UInt32($184D2206);
  LIZARDF_MAGIC_LZ5V1     = UInt32($184D2205);  // old, incompatible 
  LIZARDF_SKIPPABLE_START = UInt32($184D2A50);
  LIZARDF_SKIPPABLE_END   = UInt32($184D2A5F);
  LIZARDF_BLOCKUNCOMP     = UInt32($80000000);

  FLG_VERSION_MASK    = $C0;
  FLG_BLOCK_CHECKSUM  = $10;
  FLG_CONTENT_SIZE    = $08;
  FLG_CONTENT_CHECKSUM= $04;

  // Encoder uses blockSizeID=1 = 128 KB blocks 
  ENC_BLOCK_ID   = 1;
  ENC_BLOCK_SIZE = 128 * 1024;

  // FLG = 0x60: version=01 | blockIndep=1 | no blockChecksum
  //                        | no contentSize | no contentChecksum 
  ENC_FLG = $60;
  ENC_BD  = ENC_BLOCK_ID shl 4;   // = $10 

  BLOCK_SIZES: array[1..7] of Integer = (
    128*1024, 256*1024, 1*1024*1024, 4*1024*1024,
    16*1024*1024, 64*1024*1024, 256*1024*1024);

// ===================================================================
//  Low-level stream helpers
//  =================================================================== 

// Read exactly n bytes; returns False on short read or n=0 with n>0. 
function ReadExact(S: TStream; buf: PByte; n: Integer): Boolean;
begin
  Result := (n = 0) or (S.Read(buf^, n) = n);
end;

// Read / discard n bytes (works on non-seekable streams). 
function SkipBytes(S: TStream; n: Integer): Boolean;
const SKIP_BUF = 4096;
var
  tmp: array[0..SKIP_BUF-1] of Byte;
  chunk, got: Integer;
begin
  Result := True;
  while n > 0 do begin
    chunk := n;
    if chunk > SKIP_BUF then chunk := SKIP_BUF;
    got := S.Read(tmp[0], chunk);
    if got <= 0 then begin Result := False; Exit; end;
    Dec(n, got);
  end;
end;

function ReadLE32(S: TStream; out v: UInt32): Boolean;
var b: array[0..3] of Byte;
begin
  Result := S.Read(b[0], 4) = 4;
  if Result then
    v := UInt32(b[0]) or (UInt32(b[1]) shl 8) or
         (UInt32(b[2]) shl 16) or (UInt32(b[3]) shl 24);
end;

function ReadLE64(S: TStream; out v: UInt64): Boolean;
var
  lo, hi: UInt32;
begin
  Result := ReadLE32(S, lo) and ReadLE32(S, hi);
  if Result then v := UInt64(lo) or (UInt64(hi) shl 32);
end;

procedure WriteLE32(S: TStream; v: UInt32);
var b: array[0..3] of Byte;
begin
  b[0] := v          and $FF;
  b[1] := (v shr 8)  and $FF;
  b[2] := (v shr 16) and $FF;
  b[3] := (v shr 24) and $FF;
  S.WriteBuffer(b[0], 4);
end;

// ===================================================================
//  Internal compress
//  =================================================================== 

function DoCompress(Infile, Outfile: TStream; Level: Integer): Integer;
var
  hdr: array[0..1] of Byte;
  HC: Byte;
  inBuf:  array of Byte;
  outBuf: array of Byte;
  bound, blkRead, compSize: Integer;
  written: Integer;
begin
  Result := -1;

  SetLength(inBuf,  ENC_BLOCK_SIZE);
  bound := Lizard_compressBound(ENC_BLOCK_SIZE);
  SetLength(outBuf, bound);

  // --- frame header ------------------------------------------------- 
  hdr[0] := ENC_FLG;
  hdr[1] := ENC_BD;
  // HC = (XXH32(FLG||BD, 2, 0) >> 8) & 0xFF 
  HC := Byte((XXH32(@hdr[0], 2, 0) shr 8) and $FF);

  WriteLE32(Outfile, LIZARDF_MAGIC);
  Outfile.WriteBuffer(hdr[0], 2);
  Outfile.WriteBuffer(HC,     1);
  written := 7;  // magic(4) + FLG(1) + BD(1) + HC(1) 

  // --- compressed blocks -------------------------------------------- 
  repeat
    blkRead := Infile.Read(inBuf[0], ENC_BLOCK_SIZE);
    if blkRead <= 0 then Break;

    compSize := Lizard_compress(@inBuf[0], @outBuf[0],
                                blkRead, bound, Level);
    if compSize > 0 then begin
      // compressed block 
      WriteLE32(Outfile, UInt32(compSize));
      Outfile.WriteBuffer(outBuf[0], compSize);
      Inc(written, 4 + compSize);
    end else begin
      // fallback: store uncompressed (bit31 = 1) 
      WriteLE32(Outfile, UInt32(blkRead) or LIZARDF_BLOCKUNCOMP);
      Outfile.WriteBuffer(inBuf[0], blkRead);
      Inc(written, 4 + blkRead);
    end;
  until False;

  // --- end mark ----------------------------------------------------- 
  WriteLE32(Outfile, 0);
  Inc(written, 4);

  Result := written;
end;

// ===================================================================
//  Internal decompress
//  =================================================================== 

function DoDecompress(Infile, Outfile: TStream): Integer;
var
  magic, skipSize: UInt32;
  FLG, BD, HC, HCcheck: Byte;
  hdrBuf: array[0..9] of Byte;
  hdrLen: Integer;
  blockSizeID, maxBlk: Integer;
  hasBlkCk, hasContSz, hasContCk: Boolean;
  contentSize: UInt64;
  compBuf, decompBuf: array of Byte;
  blkHdr: UInt32;
  blkData, res, written: Integer;
begin
  Result  := -1;
  written := 0;
  magic   := 0;

  // --- skip leading skippable frames -------------------------------- 
  while ReadLE32(Infile, magic) do begin
    if (magic < LIZARDF_SKIPPABLE_START) or
       (magic > LIZARDF_SKIPPABLE_END) then Break;
    // read payload size and skip payload 
    if not ReadLE32(Infile, skipSize) then Exit;
    if not SkipBytes(Infile, skipSize) then Exit;
  end;

  // --- validate main magic ------------------------------------------ 
  if magic = LIZARDF_MAGIC_LZ5V1 then Exit;  // old LZ5 v1.x, not supported 
  if magic <> LIZARDF_MAGIC      then Exit;  // unknown format 

  // --- FLG + BD ----------------------------------------------------- 
  if (Infile.Read(FLG, 1) <> 1) or
     (Infile.Read(BD,  1) <> 1) then Exit;

  if ((FLG and FLG_VERSION_MASK) shr 6) <> 1 then Exit;  // version must be 1 

  hasBlkCk  := (FLG and FLG_BLOCK_CHECKSUM)   <> 0;
  hasContSz := (FLG and FLG_CONTENT_SIZE)      <> 0;
  hasContCk := (FLG and FLG_CONTENT_CHECKSUM)  <> 0;

  blockSizeID := (BD shr 4) and 7;
  if (blockSizeID < 1) or (blockSizeID > 7) then Exit;
  maxBlk := BLOCK_SIZES[blockSizeID];

  // --- HC: hash covers FLG + BD + optional 8-byte content size ------ 
  hdrBuf[0] := FLG;
  hdrBuf[1] := BD;
  hdrLen    := 2;

  if hasContSz then begin
    if not ReadLE64(Infile, contentSize) then Exit;
    hdrBuf[2] := Byte(contentSize);
    hdrBuf[3] := Byte(contentSize shr 8);
    hdrBuf[4] := Byte(contentSize shr 16);
    hdrBuf[5] := Byte(contentSize shr 24);
    hdrBuf[6] := Byte(contentSize shr 32);
    hdrBuf[7] := Byte(contentSize shr 40);
    hdrBuf[8] := Byte(contentSize shr 48);
    hdrBuf[9] := Byte(contentSize shr 56);
    hdrLen    := 10;
  end;

  HC := Byte((XXH32(@hdrBuf[0], hdrLen, 0) shr 8) and $FF);
  if Infile.Read(HCcheck, 1) <> 1 then Exit;
  if HC <> HCcheck then Exit;  // header checksum mismatch 

  // --- allocate block buffers --------------------------------------- 
  SetLength(compBuf,   maxBlk);
  SetLength(decompBuf, maxBlk);

  // --- block loop --------------------------------------------------- 
  while ReadLE32(Infile, blkHdr) do begin
    if blkHdr = 0 then Break;  // end mark 

    blkData := Integer(blkHdr and $7FFFFFFF);
    if blkData > maxBlk then Exit;  // corrupt: too large 
    if not ReadExact(Infile, @compBuf[0], blkData) then Exit;

    if (blkHdr and LIZARDF_BLOCKUNCOMP) <> 0 then begin
      // uncompressed block – copy verbatim 
      Outfile.WriteBuffer(compBuf[0], blkData);
      Inc(written, blkData);
    end else begin
      // compressed block 
      res := Lizard_decompress_safe(@compBuf[0], @decompBuf[0],
                                    blkData, maxBlk);
      if res <= 0 then Exit;
      Outfile.WriteBuffer(decompBuf[0], res);
      Inc(written, res);
    end;

    // skip optional per-block checksum (4 bytes) 
    if hasBlkCk then
      if not SkipBytes(Infile, 4) then Exit;
  end;

  // skip optional content checksum (4 bytes) 
  if hasContCk then SkipBytes(Infile, 4);

  Result := written;
end;

// ===================================================================
//  Public API
// =================================================================== 

function LZ5CompressStreams(Infile, Outfile: TStream): Integer;
// Compresses using fastLZ4 tokens (level 10 = LIZARD_MIN_CLEVEL). 
begin
  Result := DoCompress(Infile, Outfile, LIZARD_MIN_CLEVEL);
end;

function LIZCompressStreams(Infile, Outfile: TStream): Integer;
// Compresses using LIZv1 tokens (level 20 = first LIZv1 level). 
begin
  Result := DoCompress(Infile, Outfile, 20);
end;

function LZ5DecompressStreams(Infile, Outfile: TStream): Integer;
// Decodes any Lizard frame (magic $184D2206) regardless of level. 
begin
  Result := DoDecompress(Infile, Outfile);
end;

function LIZDecompressStreams(Infile, Outfile: TStream): Integer;
// Identical to LZ5DecompressStreams – the frame format is the same. 
begin
  Result := DoDecompress(Infile, Outfile);
end;

// =================================================================== 
// HElper functions - LIZ
// =================================================================== 

function LIZCompressFile(const Infilename, Outfilename: String): Integer;
var
  InFile: TFileStream;
  OutFile: TFileStream;
begin
  Result := 0;
  InFile := nil;
  OutFile := nil;

  try
    try
      InFile := TFileStream.Create(Infilename, fmOpenRead or fmShareDenyWrite);
    except
      Result := -1;
      Exit;
    end;

    try
      try
        OutFile := TFileStream.Create(Outfilename, fmCreate);
      except
        Result := -3;
        Exit;
      end;

      Result := LIZCompressStreams(InFile, OutFile);
    finally
      OutFile.Free;
    end;
  finally
    InFile.Free;
  end;
end;

function LIZDecompressFile(const Infilename, Outfilename: String): Integer;
var
  InFile: TFileStream;
  OutFile: TFileStream;
begin
  Result := 0;
  InFile := nil;
  OutFile := nil;

  try
    try
      InFile := TFileStream.Create(Infilename, fmOpenRead or fmShareDenyWrite);
    except
      Result := -1;
      Exit;
    end;

    try
      try
        OutFile := TFileStream.Create(Outfilename, fmCreate);
      except
        Result := -3;
        Exit;
      end;

      Result := LIZDecompressStreams(InFile, OutFile);
    finally
      OutFile.Free;
    end;
  finally
    InFile.Free;
  end;
end;

function LIZ(Uncompressed: AnsiString): AnsiString;
var
  InStream, OutStream: TMemoryStream;
begin
  Result := '';
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  try
    // put data in a stream
    if Length(Uncompressed) > 0 then
      InStream.WriteBuffer(Pointer(Uncompressed)^, Length(Uncompressed));
    InStream.Position := 0;

    // pack
    if LIZCompressStreams(InStream, OutStream) <> 0 then
      Exit;

    // stream to string
    SetLength(Result, OutStream.Size);
    if OutStream.Size > 0 then
    begin
      OutStream.Position := 0;
      OutStream.ReadBuffer(Pointer(Result)^, OutStream.Size);
    end;
  finally
    OutStream.Free;
    InStream.Free;
  end;
end;

function UnLIZ(Compressed: AnsiString): AnsiString;
var
  InStream, OutStream: TMemoryStream;
begin
  Result := '';
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  try
    // string to stream
    if Length(Compressed) > 0 then
      InStream.WriteBuffer(Pointer(Compressed)^, Length(Compressed));
    InStream.Position := 0;

    // unpack
    if LIZDecompressStreams(InStream, OutStream) <> 0 then
      Exit;

    // stream to string
    SetLength(Result, OutStream.Size);
    if OutStream.Size > 0 then
    begin
      OutStream.Position := 0;
      OutStream.ReadBuffer(Pointer(Result)^, OutStream.Size);
    end;
  finally
    OutStream.Free;
    InStream.Free;
  end;
end;


// =================================================================== 
// HElper functions - LZ5
// =================================================================== 

function LZ5CompressFile(const Infilename, Outfilename: String): Integer;
var
  InFile: TFileStream;
  OutFile: TFileStream;
begin
  Result := 0;
  InFile := nil;
  OutFile := nil;

  try
    try
      InFile := TFileStream.Create(Infilename, fmOpenRead or fmShareDenyWrite);
    except
      Result := -1;
      Exit;
    end;

    try
      try
        OutFile := TFileStream.Create(Outfilename, fmCreate);
      except
        Result := -3;
        Exit;
      end;

      Result := LZ5CompressStreams(InFile, OutFile);
    finally
      OutFile.Free;
    end;
  finally
    InFile.Free;
  end;
end;

function LZ5DecompressFile(const Infilename, Outfilename: String): Integer;
var
  InFile: TFileStream;
  OutFile: TFileStream;
begin
  Result := 0;
  InFile := nil;
  OutFile := nil;

  try
    try
      InFile := TFileStream.Create(Infilename, fmOpenRead or fmShareDenyWrite);
    except
      Result := -1;
      Exit;
    end;

    try
      try
        OutFile := TFileStream.Create(Outfilename, fmCreate);
      except
        Result := -3;
        Exit;
      end;

      Result := LZ5DecompressStreams(InFile, OutFile);
    finally
      OutFile.Free;
    end;
  finally
    InFile.Free;
  end;
end;

function LZ5(Uncompressed: AnsiString): AnsiString;
var
  InStream, OutStream: TMemoryStream;
begin
  Result := '';
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  try
    // put data in a stream
    if Length(Uncompressed) > 0 then
      InStream.WriteBuffer(Pointer(Uncompressed)^, Length(Uncompressed));
    InStream.Position := 0;

    // pack
    if LZ5CompressStreams(InStream, OutStream) <> 0 then
      Exit;

    // stream to string
    SetLength(Result, OutStream.Size);
    if OutStream.Size > 0 then
    begin
      OutStream.Position := 0;
      OutStream.ReadBuffer(Pointer(Result)^, OutStream.Size);
    end;
  finally
    OutStream.Free;
    InStream.Free;
  end;
end;

function UnLZ5(Compressed: AnsiString): AnsiString;
var
  InStream, OutStream: TMemoryStream;
begin
  Result := '';
  InStream := TMemoryStream.Create;
  OutStream := TMemoryStream.Create;
  try
    // string to stream
    if Length(Compressed) > 0 then
      InStream.WriteBuffer(Pointer(Compressed)^, Length(Compressed));
    InStream.Position := 0;

    // unpack
    if LZ5DecompressStreams(InStream, OutStream) <> 0 then
      Exit;

    // stream to string
    SetLength(Result, OutStream.Size);
    if OutStream.Size > 0 then
    begin
      OutStream.Position := 0;
      OutStream.ReadBuffer(Pointer(Result)^, OutStream.Size);
    end;
  finally
    OutStream.Free;
    InStream.Free;
  end;
end;

end.
