unit lz5;

// Free Pascal port of Lizard / LZ5 compressor+decompressor
// Original C code (c) Przemyslaw Skibinski, Yann Collet (BSD-2)
// Pascal port: decompression levels 10-29, compression levels 10-17
// No Huffman entropy coding (levels 30-49 not supported).
// Author: www.xelitan.com
// License: BSD-2

{$mode objfpc}{$H+}
{$inline on}
{$Q-}{$R-}
{$pointermath on}

interface

const
  LIZARD_MIN_CLEVEL     = 10;
  LIZARD_MAX_CLEVEL     = 29;
  LIZARD_DEFAULT_CLEVEL = 17;
  LIZARD_MAX_INPUT_SIZE = $7E000000;
  LIZARD_BLOCK_SIZE     = 1 shl 17;   { 131072 }
  LIZARD_DICT_SIZE      = 1 shl 24;   { 16 MB }

function Lizard_compressBound(inputSize: Integer): Integer;
function Lizard_compress(src: PByte; dst: PByte;
                         srcSize, maxDstSize, compressionLevel: Integer): Integer;
function Lizard_decompress_safe(source: PByte; dest: PByte;
                                compressedSize, maxDecompressedSize: Integer): Integer;
function Lizard_decompress_safe_partial(source: PByte; dest: PByte;
                                        compressedSize, targetOutputSize,
                                        maxDecompressedSize: Integer): Integer;

implementation

uses SysUtils;

const
  MINMATCH        = 4;
  WILDCOPYLENGTH  = 16;
  LASTLITERALS    = WILDCOPYLENGTH;
  MFLIMIT         = WILDCOPYLENGTH + MINMATCH;
  LIZARD_MIN_LENGTH = MFLIMIT + 1;

  ML_BITS_LZ4  = 4;
  ML_MASK_LZ4  = 15;
  RUN_BITS_LZ4 = 4;
  RUN_MASK_LZ4 = 15;

  RUN_BITS_LIZv1   = 3;
  ML_RUN_BITS      = 7;
  MAX_SHORT_LITLEN  = 7;
  MAX_SHORT_MATCHLEN = 15;
  LIZARD_LAST_LONG_OFF = 31;
  MM_LONGOFF           = 16;

  LIZARD_FLAG_LITERALS     = 1;
  LIZARD_FLAG_FLAGS        = 2;
  LIZARD_FLAG_OFFSET16     = 4;
  LIZARD_FLAG_OFFSET24     = 8;
  LIZARD_FLAG_LEN          = 16;
  LIZARD_FLAG_UNCOMPRESSED = 128;

  LIZARD_MAX_16BIT_OFFSET = 65536;

  LIZARD_BLOCK_SIZE_PAD   = LIZARD_BLOCK_SIZE + 32;
  LIZARD_COMPRESS_ADD_BUF = 5 * LIZARD_BLOCK_SIZE_PAD;

  LIZARD_WINDOWLOG_LZ4  = 16;
  LIZARD_HASHLOG_LZ4    = 18;
  LIZARD_HASHLOG_LZ4SM  = 12;
  LIZARD_CHAINLOG_LZ4   = 16;
  LIZARD_WINDOWLOG_LIZv1 = 22;
  LIZARD_HASHLOG_LIZv1   = 18;

  LIZARD_INIT_LAST_OFFSET = 0;
  LIZARD_HC_MIN_OFFSET    = 8;
  LIZARD_FAST_MIN_OFFSET  = 8;
  LIZARD_SKIP_TRIGGER     = 6;

  PRIME4: UInt32 = 2654435761;
  PRIME5: UInt64 = 889523592379;

  noDict        = 0;
  withPrefix64k = 1;
  usingExtDict  = 2;

type
  TParserType    = (ptFastSmall, ptFast, ptNoChain, ptHashChain);
  TDecompressType = (dtLZ4, dtLIZv1);

  TCompressParams = record
    windowLog:     UInt32;
    contentLog:    UInt32;
    hashLog:       UInt32;
    searchNum:     UInt32;
    searchLength:  UInt32;
    parserType:    TParserType;
    decompressType: TDecompressType;
  end;

  PLizard_dstream = ^TLizard_dstream;
  TLizard_dstream = record
    offset16Ptr: PByte;
    offset24Ptr: PByte;
    lenPtr:      PByte;
    literalsPtr: PByte;
    flagsPtr:    PByte;
    offset16End: PByte;
    offset24End: PByte;
    lenEnd:      PByte;
    literalsEnd: PByte;
    flagsEnd:    PByte;
    last_off:    IntPtr;
  end;

  PLizardStream = ^TLizardStream;
  TLizardStream = record
    endPtr:       PByte;
    base:         PByte;
    dictBase:     PByte;
    dictLimit:    UInt32;
    lowLimit:     UInt32;
    nextToUpdate: UInt32;
    allocatedMemory: UInt32;
    compressionLevel: Integer;
    params:       TCompressParams;
    hashTableSize: UInt32;
    chainTableSize: UInt32;
    chainTable:   PUInt32;
    hashTable:    PUInt32;
    last_off:     Integer;
    offset16Base: PByte;
    offset24Base: PByte;
    lenBase:      PByte;
    literalsBase: PByte;
    flagsBase:    PByte;
    offset16Ptr:  PByte;
    offset24Ptr:  PByte;
    lenPtr:       PByte;
    literalsPtr:  PByte;
    flagsPtr:     PByte;
    offset16End:  PByte;
    offset24End:  PByte;
    lenEnd:       PByte;
    literalsEnd:  PByte;
    flagsEnd:     PByte;
    srcBase:      PByte;
    destBase:     PByte;
    diffBase:     PByte;
  end;

const
  LIZARD_PARAMS: array[0..7] of TCompressParams = (
    (windowLog:16; contentLog:0;  hashLog:LIZARD_HASHLOG_LZ4SM; searchNum:0;   searchLength:4; parserType:ptFastSmall; decompressType:dtLZ4),
    (windowLog:16; contentLog:0;  hashLog:LIZARD_HASHLOG_LZ4;   searchNum:0;   searchLength:4; parserType:ptFast;      decompressType:dtLZ4),
    (windowLog:16; contentLog:0;  hashLog:LIZARD_HASHLOG_LZ4;   searchNum:0;   searchLength:4; parserType:ptNoChain;   decompressType:dtLZ4),
    (windowLog:16; contentLog:16; hashLog:LIZARD_HASHLOG_LZ4;   searchNum:2;   searchLength:5; parserType:ptHashChain; decompressType:dtLZ4),
    (windowLog:16; contentLog:16; hashLog:LIZARD_HASHLOG_LZ4;   searchNum:4;   searchLength:5; parserType:ptHashChain; decompressType:dtLZ4),
    (windowLog:16; contentLog:16; hashLog:LIZARD_HASHLOG_LZ4;   searchNum:8;   searchLength:5; parserType:ptHashChain; decompressType:dtLZ4),
    (windowLog:16; contentLog:16; hashLog:LIZARD_HASHLOG_LZ4;   searchNum:16;  searchLength:4; parserType:ptHashChain; decompressType:dtLZ4),
    (windowLog:16; contentLog:16; hashLog:LIZARD_HASHLOG_LZ4;   searchNum:256; searchLength:4; parserType:ptHashChain; decompressType:dtLZ4)
  );

{ ---- memory primitives ---- }

function MEM_readLE16(p: PByte): UInt16; inline;
begin
  Result := UInt16(p[0]) or (UInt16(p[1]) shl 8);
end;

function MEM_readLE24(p: PByte): UInt32; inline;
begin
  Result := UInt32(p[0]) or (UInt32(p[1]) shl 8) or (UInt32(p[2]) shl 16);
end;

function MEM_read32(p: PByte): UInt32; inline;
var v: UInt32;
begin Move(p^, v, 4); Result := v; end;

function MEM_read64(p: PByte): UInt64; inline;
var v: UInt64;
begin Move(p^, v, 8); Result := v; end;

procedure MEM_writeLE16(p: PByte; v: UInt16); inline;
begin p[0] := Byte(v); p[1] := Byte(v shr 8); end;

procedure MEM_writeLE24(p: PByte; v: UInt32); inline;
begin p[0] := Byte(v); p[1] := Byte(v shr 8); p[2] := Byte(v shr 16); end;

procedure MEM_copy8(dst, src: PByte); inline;
begin Move(src^, dst^, 8); end;

procedure Lizard_wildCopy(dst, src, dstEnd: PByte); inline;
begin
  repeat MEM_copy8(dst, src); Inc(dst,8); Inc(src,8); until dst >= dstEnd;
end;

procedure Lizard_wildCopy16(dst, src, dstEnd: PByte); inline;
begin
  repeat
    MEM_copy8(dst, src); MEM_copy8(dst+8, src+8);
    Inc(dst,16); Inc(src,16);
  until dst >= dstEnd;
end;

function Lizard_count(pIn, pMatch, pInLimit: PByte): UInt32;
var
  pStart: PByte;
  diff, tmp: NativeUInt;
  nb: Integer;
begin
  pStart := pIn;
  while pIn + SizeOf(NativeUInt) - 1 < pInLimit do begin
    Move(pIn^,    diff, SizeOf(NativeUInt));
    Move(pMatch^, tmp,  SizeOf(NativeUInt));
    diff := diff xor tmp;
    if diff = 0 then begin
      Inc(pIn,    SizeOf(NativeUInt));
      Inc(pMatch, SizeOf(NativeUInt));
    end else begin
      nb := 0;
      while (nb < SizeOf(NativeUInt)) and ((diff and $FF) = 0) do begin
        diff := diff shr 8; Inc(nb);
      end;
      Inc(pIn, nb);
      Exit(UInt32(pIn - pStart));
    end;
  end;
  if (SizeOf(NativeUInt) = 8) and (pIn + 3 < pInLimit) and (MEM_read32(pIn) = MEM_read32(pMatch)) then begin
    Inc(pIn,4); Inc(pMatch,4);
  end;
  if (pIn+1 < pInLimit) and (MEM_readLE16(pIn) = MEM_readLE16(pMatch)) then begin
    Inc(pIn,2); Inc(pMatch,2);
  end;
  if (pIn < pInLimit) and (pIn^ = pMatch^) then Inc(pIn);
  Result := UInt32(pIn - pStart);
end;

function Lizard_count_2segments(ip, match, iEnd, mEnd, iStart: PByte): NativeUInt;
var vEnd: PByte; ml: NativeUInt;
begin
  if PtrUInt(ip) + PtrUInt(mEnd - match) < PtrUInt(iEnd) then
    vEnd := ip + (mEnd - match)
  else vEnd := iEnd;
  ml := Lizard_count(ip, match, vEnd);
  if match + ml <> mEnd then Exit(ml);
  Result := ml + Lizard_count(ip + ml, iStart, iEnd);
end;

{ ---- hash functions ---- }

function Lizard_hash4(u: UInt32; h: UInt32): UInt32; inline;
var t: UInt32;
begin t := UInt32(u * UInt32(PRIME4)); Result := t shr (32 - h); end;

function Lizard_hash4Ptr(p: PByte; h: UInt32): UInt32; inline;
begin Result := Lizard_hash4(MEM_read32(p), h); end;

function Lizard_hash5(u: UInt64; h: UInt32): UInt32; inline;
begin Result := UInt32((u * PRIME5) shl (64-40) shr (64-h)); end;

function Lizard_hash5Ptr(p: PByte; h: UInt32): UInt32; inline;
begin Result := Lizard_hash5(MEM_read64(p), h); end;

function Lizard_hashPositionH(p: PByte; h: UInt32): UInt32; inline;
begin
  {$ifdef CPU64} Result := Lizard_hash5Ptr(p, h);
  {$else}        Result := Lizard_hash4Ptr(p, h); {$endif}
end;

function Lizard_hashPtr(p: PByte; hBits, mls: UInt32): UInt32; inline;
begin
  if mls >= 5 then Result := Lizard_hash5Ptr(p, hBits)
  else             Result := Lizard_hash4Ptr(p, hBits);
end;

{ ---- compression context helpers ---- }

function Lizard_verifyLevel(level: Integer): Integer; inline;
begin
  if level > 17 then level := 17;
  if level < LIZARD_MIN_CLEVEL then level := LIZARD_DEFAULT_CLEVEL;
  Result := level;
end;

function Lizard_sizeofState(compressionLevel: Integer): Integer;
var p: TCompressParams; ht, ct: UInt32;
begin
  compressionLevel := Lizard_verifyLevel(compressionLevel);
  p  := LIZARD_PARAMS[compressionLevel - LIZARD_MIN_CLEVEL];
  ht := SizeOf(UInt32) * (UInt32(1) shl p.hashLog);
  ct := SizeOf(UInt32) * (UInt32(1) shl p.contentLog);
  Result := SizeOf(TLizardStream) + ht + ct + LIZARD_COMPRESS_ADD_BUF;
end;

procedure Lizard_initBlockState(ctx: PLizardStream); inline;
begin
  ctx^.offset16Ptr := ctx^.offset16Base;
  ctx^.offset24Ptr := ctx^.offset24Base;
  ctx^.lenPtr      := ctx^.lenBase;
  ctx^.literalsPtr := ctx^.literalsBase;
  ctx^.flagsPtr    := ctx^.flagsBase;
  ctx^.last_off    := LIZARD_INIT_LAST_OFFSET;
end;

procedure Lizard_initCtx(ctx: PLizardStream; start: PByte); inline;
begin
  ctx^.nextToUpdate := LIZARD_DICT_SIZE;
  ctx^.base         := start - LIZARD_DICT_SIZE;
  ctx^.endPtr       := start;
  ctx^.dictBase     := start - LIZARD_DICT_SIZE;
  ctx^.dictLimit    := LIZARD_DICT_SIZE;
  ctx^.lowLimit     := LIZARD_DICT_SIZE;
  ctx^.last_off     := LIZARD_INIT_LAST_OFFSET;
end;

procedure Lizard_initStream(ctx: PLizardStream; compressionLevel: Integer);
var p: TCompressParams; ht, ct: UInt32; b: PByte;
begin
  compressionLevel := Lizard_verifyLevel(compressionLevel);
  p  := LIZARD_PARAMS[compressionLevel - LIZARD_MIN_CLEVEL];
  ht := SizeOf(UInt32) * (UInt32(1) shl p.hashLog);
  ct := SizeOf(UInt32) * (UInt32(1) shl p.contentLog);

  ctx^.params           := p;
  ctx^.compressionLevel := compressionLevel;
  ctx^.hashTableSize    := ht;
  ctx^.chainTableSize   := ct;
  ctx^.hashTable        := PUInt32(PByte(ctx) + SizeOf(TLizardStream));
  ctx^.chainTable       := PUInt32(PByte(ctx^.hashTable) + ht);

  b := PByte(ctx^.chainTable) + ct;
  ctx^.literalsBase := b;
  ctx^.flagsBase    := b + LIZARD_BLOCK_SIZE_PAD;
  ctx^.lenBase      := ctx^.flagsBase    + LIZARD_BLOCK_SIZE_PAD;
  ctx^.offset16Base := ctx^.lenBase      + LIZARD_BLOCK_SIZE_PAD;
  ctx^.offset24Base := ctx^.offset16Base + LIZARD_BLOCK_SIZE_PAD;

  ctx^.literalsEnd  := ctx^.flagsBase;
  ctx^.flagsEnd     := ctx^.lenBase;
  ctx^.lenEnd       := ctx^.offset16Base;
  ctx^.offset16End  := ctx^.offset24Base;
  ctx^.offset24End  := ctx^.offset24Base + LIZARD_BLOCK_SIZE_PAD;

  FillChar(ctx^.hashTable^, ht, 0);
end;

{ ---- LZ4-mode sequence encoder ---- }

function Lizard_encodeSequence_LZ4(ctx: PLizardStream; var ip, anchor: PByte;
                                    matchLen: NativeUInt; match: PByte): Boolean;
var
  token: PByte;
  litLen, mlen, extra: NativeUInt;
begin
  litLen := NativeUInt(ip - anchor);
  token  := ctx^.flagsPtr;  Inc(ctx^.flagsPtr);

  if litLen >= RUN_MASK_LZ4 then begin
    token^ := RUN_MASK_LZ4;
    extra  := litLen - RUN_MASK_LZ4;
    if extra >= (1 shl 16) then begin
      ctx^.literalsPtr^ := 255; MEM_writeLE24(ctx^.literalsPtr+1, UInt32(extra)); Inc(ctx^.literalsPtr,4);
    end else if extra >= 254 then begin
      ctx^.literalsPtr^ := 254; MEM_writeLE16(ctx^.literalsPtr+1, UInt16(extra)); Inc(ctx^.literalsPtr,3);
    end else begin ctx^.literalsPtr^ := Byte(extra); Inc(ctx^.literalsPtr); end;
  end else token^ := Byte(litLen);

  if litLen > 0 then begin
    Lizard_wildCopy(ctx^.literalsPtr, anchor, ctx^.literalsPtr + litLen);
    Inc(ctx^.literalsPtr, litLen);
  end;

  MEM_writeLE16(ctx^.literalsPtr, UInt16(PtrUInt(ip) - PtrUInt(match)));
  Inc(ctx^.literalsPtr, 2);

  mlen := matchLen - MINMATCH;
  if mlen >= ML_MASK_LZ4 then begin
    token^ := token^ or (ML_MASK_LZ4 shl RUN_BITS_LZ4);
    extra  := mlen - ML_MASK_LZ4;
    if extra >= (1 shl 16) then begin
      ctx^.literalsPtr^ := 255; MEM_writeLE24(ctx^.literalsPtr+1, UInt32(extra)); Inc(ctx^.literalsPtr,4);
    end else if extra >= 254 then begin
      ctx^.literalsPtr^ := 254; MEM_writeLE16(ctx^.literalsPtr+1, UInt16(extra)); Inc(ctx^.literalsPtr,3);
    end else begin ctx^.literalsPtr^ := Byte(extra); Inc(ctx^.literalsPtr); end;
  end else token^ := token^ or Byte(mlen shl RUN_BITS_LZ4);

  Inc(ip, matchLen);  anchor := ip;
  Result := False;
end;

function Lizard_encodeLastLiterals_LZ4(ctx: PLizardStream; var ip, anchor: PByte): Boolean;
var n: NativeUInt;
begin
  n := NativeUInt(ip - anchor);
  if n > 0 then Move(anchor^, ctx^.literalsPtr^, n);
  Inc(ctx^.literalsPtr, n);
  Result := False;
end;

{ ---- write block ---- }

function Lizard_writeBlock(ctx: PLizardStream; ip: PByte; inputSize: UInt32;
                            var op: PByte; oend: PByte): Boolean;
var
  flagsLen, litLen, lenLen, off16Len, off24Len, sum, blk: UInt32;
  start: PByte;
  slen: UInt32;
  sbase: PByte;
begin
  flagsLen := UInt32(ctx^.flagsPtr    - ctx^.flagsBase);
  litLen   := UInt32(ctx^.literalsPtr - ctx^.literalsBase);
  lenLen   := UInt32(ctx^.lenPtr      - ctx^.lenBase);
  off16Len := UInt32(ctx^.offset16Ptr - ctx^.offset16Base);
  off24Len := UInt32(ctx^.offset24Ptr - ctx^.offset24Base);
  sum      := flagsLen + litLen + lenLen + off16Len + off24Len;
  start    := op;

  { uncompressed shortcut }
  if (litLen < WILDCOPYLENGTH) or (sum + 5*3 + 1 > inputSize) then begin
    if PtrUInt(oend - op) < inputSize + 4 then begin Result := True; Exit; end;
    op^ := LIZARD_FLAG_UNCOMPRESSED; Inc(op);
    MEM_writeLE24(op, inputSize); Inc(op,3);
    Move(ip^, op^, inputSize); Inc(op, inputSize);
    Result := False; Exit;
  end;

  op^ := 0;  Inc(op);   { header flags: no Huffman }

  { write 5 streams: len, offset16, offset24, flags, literals }
  sbase := ctx^.lenBase;      slen := lenLen;
  if op + 3 + slen > oend then begin Result := True; Exit; end;
  MEM_writeLE24(op, slen); Inc(op,3); if slen>0 then Move(sbase^, op^, slen); Inc(op, slen);

  sbase := ctx^.offset16Base; slen := off16Len;
  if op + 3 + slen > oend then begin Result := True; Exit; end;
  MEM_writeLE24(op, slen); Inc(op,3); if slen>0 then Move(sbase^, op^, slen); Inc(op, slen);

  sbase := ctx^.offset24Base; slen := off24Len;
  if op + 3 + slen > oend then begin Result := True; Exit; end;
  MEM_writeLE24(op, slen); Inc(op,3); if slen>0 then Move(sbase^, op^, slen); Inc(op, slen);

  sbase := ctx^.flagsBase;    slen := flagsLen;
  if op + 3 + slen > oend then begin Result := True; Exit; end;
  MEM_writeLE24(op, slen); Inc(op,3); if slen>0 then Move(sbase^, op^, slen); Inc(op, slen);

  sbase := ctx^.literalsBase; slen := litLen;
  if op + 3 + slen > oend then begin Result := True; Exit; end;
  MEM_writeLE24(op, slen); Inc(op,3); if slen>0 then Move(sbase^, op^, slen); Inc(op, slen);

  blk := UInt32(op - start);
  if blk + (blk div 32) + 512 > inputSize then begin
    op := start;
    if PtrUInt(oend - op) < inputSize + 4 then begin Result := True; Exit; end;
    op^ := LIZARD_FLAG_UNCOMPRESSED; Inc(op);
    MEM_writeLE24(op, inputSize); Inc(op,3);
    Move(ip^, op^, inputSize); Inc(op, inputSize);
  end;
  Result := False;
end;

{ ---- hash chain insert ---- }

procedure Lizard_Insert_HC(ctx: PLizardStream; ip: PByte);
var
  chainTable, hashTable: PUInt32;
  base: PByte;
  target, idx, contentMask, maxDist, delta, h: UInt32;
begin
  chainTable  := ctx^.chainTable;
  hashTable   := ctx^.hashTable;
  base        := ctx^.base;
  target      := UInt32(ip - base);
  idx         := ctx^.nextToUpdate;
  contentMask := (UInt32(1) shl ctx^.params.contentLog) - 1;
  maxDist     := (UInt32(1) shl ctx^.params.windowLog) - 1;

  while idx < target do begin
    h := Lizard_hashPtr(base + idx, ctx^.params.hashLog, ctx^.params.searchLength);
    delta := idx - hashTable[h];
    if delta > maxDist then delta := maxDist;
    chainTable[idx and contentMask] := delta;
    if (hashTable[h] >= idx) or (idx >= hashTable[h] + LIZARD_HC_MIN_OFFSET) then
      hashTable[h] := idx;
    Inc(idx);
  end;
  ctx^.nextToUpdate := target;
end;

{ ---- fast/fastSmall parser ---- }

function Lizard_compress_fast_internal(ctx: PLizardStream;
                                        ip, iend: PByte; hashLog: UInt32): Integer;
label _last_literals, _next_match, _err;
var
  base, dictBase, dictEnd, lowPrefixPtr: PByte;
  mfend, matchlimit, anchor: PByte;
  forwardIp, match, fwdMatch: PByte;
  forwardH, h: UInt32;
  dictLimit, lowLimit, newLowLimit, maxDist, matchIndex: UInt32;
  step, searchMatchNb: UInt32;
  matchLen: NativeUInt;
  ext: Integer;
begin
  Result := 0;
  base        := ctx^.base;
  dictLimit   := ctx^.dictLimit;
  lowPrefixPtr:= base + dictLimit;
  dictBase    := ctx^.dictBase;
  dictEnd     := dictBase + dictLimit;
  mfend     := iend - MFLIMIT;
  matchlimit  := iend - LASTLITERALS;
  anchor      := ip;
  maxDist     := (UInt32(1) shl ctx^.params.windowLog) - 1;

  if UInt32(iend - ip) > UInt32(LIZARD_MAX_INPUT_SIZE) then goto _err;
  if UInt32(iend - ip) < LIZARD_MIN_LENGTH then goto _last_literals;

  if ctx^.lowLimit + maxDist >= UInt32(ip - base) then
    lowLimit := ctx^.lowLimit
  else
    lowLimit := UInt32(ip - base) - maxDist;

  ctx^.hashTable[Lizard_hashPositionH(ip, hashLog)] := UInt32(ip - base);
  Inc(ip);
  forwardH := Lizard_hashPositionH(ip, hashLog);

  repeat
    forwardIp     := ip;
    step          := 1;
    searchMatchNb := 1 shl LIZARD_SKIP_TRIGGER;
    repeat
      h         := forwardH;
      ip        := forwardIp;
      Inc(forwardIp, step);
      Inc(searchMatchNb);
      step := searchMatchNb shr LIZARD_SKIP_TRIGGER;
      if forwardIp > mfend then goto _last_literals;
      matchIndex := ctx^.hashTable[h];
      forwardH   := Lizard_hashPositionH(forwardIp, hashLog);
      ctx^.hashTable[h] := UInt32(ip - base);
      if (matchIndex < lowLimit) or (matchIndex >= UInt32(ip - base)) or
         (base + matchIndex + maxDist < ip) then Continue;
      if matchIndex >= dictLimit then begin
        match := base + matchIndex;
        if (UInt32(PtrUInt(ip) - PtrUInt(match)) >= LIZARD_FAST_MIN_OFFSET) and
           (MEM_read32(match) = MEM_read32(ip)) then begin
          matchLen := Lizard_count(ip+MINMATCH, match+MINMATCH, matchlimit);
          ext := 0;
          while (ip-ext-1 >= anchor) and (match-ext-1 >= lowPrefixPtr) and
                ((ip-ext-1)^ = (match-ext-1)^) do Inc(ext);
          Inc(matchLen, ext);  Dec(ip, ext);  Dec(match, ext);
          Break;
        end;
      end else begin
        match := dictBase + matchIndex;
        if (UInt32(PtrUInt(ip) - (PtrUInt(base)+matchIndex)) >= LIZARD_FAST_MIN_OFFSET) and
           (UInt32(dictLimit-1-matchIndex) >= 3) and
           (MEM_read32(match) = MEM_read32(ip)) then begin
          if ctx^.lowLimit + maxDist >= UInt32(ip - base) then
            newLowLimit := ctx^.lowLimit
          else
            newLowLimit := UInt32(ip - base) - maxDist;
          matchLen := Lizard_count_2segments(ip+MINMATCH, match+MINMATCH, matchlimit, dictEnd, lowPrefixPtr);
          ext := 0;
          while (ip-ext-1 >= anchor) and (UInt32(matchIndex)-ext >= newLowLimit+1) and
                ((ip-ext-1)^ = (match-ext-1)^) do Inc(ext);
          Inc(matchLen, ext);  Dec(ip, ext);
          match := base + matchIndex - ext;
          Break;
        end;
      end;
    until False;

_next_match:
    if Lizard_encodeSequence_LZ4(ctx, ip, anchor, matchLen+MINMATCH, match) then
      goto _err;
    if ip > mfend then Break;
    ctx^.hashTable[Lizard_hashPositionH(ip-2, hashLog)] := UInt32((ip-2)-base);
    matchIndex := ctx^.hashTable[Lizard_hashPositionH(ip, hashLog)];
    ctx^.hashTable[Lizard_hashPositionH(ip, hashLog)] := UInt32(ip - base);
    if (matchIndex >= lowLimit) and (matchIndex < UInt32(ip-base)) and
       (base+matchIndex+maxDist >= ip) then begin
      if matchIndex >= dictLimit then begin
        match := base + matchIndex;
        if (UInt32(PtrUInt(ip)-PtrUInt(match)) >= LIZARD_FAST_MIN_OFFSET) and
           (MEM_read32(match) = MEM_read32(ip)) then begin
          matchLen := Lizard_count(ip+MINMATCH, match+MINMATCH, matchlimit);
          goto _next_match;
        end;
      end else begin
        fwdMatch := dictBase + matchIndex;
        if (UInt32(PtrUInt(ip)-(PtrUInt(base)+matchIndex)) >= LIZARD_FAST_MIN_OFFSET) and
           (UInt32(dictLimit-1-matchIndex) >= 3) and
           (MEM_read32(fwdMatch) = MEM_read32(ip)) then begin
          matchLen := Lizard_count_2segments(ip+MINMATCH, fwdMatch+MINMATCH, matchlimit, dictEnd, lowPrefixPtr);
          match := base + matchIndex;
          goto _next_match;
        end;
      end;
    end;
    forwardH := Lizard_hashPositionH(ip+1, hashLog);
    Inc(ip);
  until False;

_last_literals:
  ip := iend;
  if Lizard_encodeLastLiterals_LZ4(ctx, ip, anchor) then goto _err;
  Result := 1;  Exit;
_err:
  Result := 0;
end;

{ ---- hashChain best-match finder ---- }

function Lizard_FindBestMatch_HC(ctx: PLizardStream; ip, iLimit: PByte;
                                  out matchPos: PByte): Integer;
var
  chainTable, hashTable: PUInt32;
  base, dictBase, dictEnd, lowPrefixPtr: PByte;
  dictLimit, lowLimit, maxDist, current, contentMask: UInt32;
  matchIndex, delta: UInt32;
  match: PByte;
  nbAttempts: Integer;
  ml, mlt: NativeUInt;
begin
  chainTable   := ctx^.chainTable;
  hashTable    := ctx^.hashTable;
  base         := ctx^.base;
  dictBase     := ctx^.dictBase;
  dictLimit    := ctx^.dictLimit;
  lowPrefixPtr := base + dictLimit;
  dictEnd      := dictBase + dictLimit;
  contentMask  := (UInt32(1) shl ctx^.params.contentLog) - 1;
  maxDist      := (UInt32(1) shl ctx^.params.windowLog) - 1;
  current      := UInt32(ip - base);
  if ctx^.lowLimit + maxDist >= current then
    lowLimit := ctx^.lowLimit
  else
    lowLimit := current - maxDist;
  nbAttempts := Integer(ctx^.params.searchNum);
  ml := 0;  matchPos := nil;

  Lizard_Insert_HC(ctx, ip);
  matchIndex := hashTable[Lizard_hashPtr(ip, ctx^.params.hashLog, ctx^.params.searchLength)];

  while (matchIndex < current) and (matchIndex >= lowLimit) and (nbAttempts > 0) do begin
    Dec(nbAttempts);
    if matchIndex >= dictLimit then begin
      match := base + matchIndex;
      if (UInt32(PtrUInt(ip)-PtrUInt(match)) >= LIZARD_HC_MIN_OFFSET) and
         ((match+ml)^ = (ip+ml)^) and (MEM_read32(match) = MEM_read32(ip)) then begin
        mlt := Lizard_count(ip+MINMATCH, match+MINMATCH, iLimit) + MINMATCH;
        if mlt > ml then begin ml := mlt; matchPos := match; end;
      end;
    end else begin
      match := dictBase + matchIndex;
      if (UInt32(PtrUInt(ip)-(PtrUInt(base)+matchIndex)) >= LIZARD_HC_MIN_OFFSET) and
         (UInt32(dictLimit-1-matchIndex) >= 3) and
         (MEM_read32(match) = MEM_read32(ip)) then begin
        mlt := Lizard_count_2segments(ip+MINMATCH, match+MINMATCH, iLimit, dictEnd, lowPrefixPtr) + MINMATCH;
        if mlt > ml then begin ml := mlt; matchPos := base + matchIndex; end;
      end;
    end;
    delta := chainTable[matchIndex and contentMask];
    if delta > matchIndex then Break;
    matchIndex := matchIndex - delta;
  end;
  Result := Integer(ml);
end;

function Lizard_GetWiderMatch_HC(ctx: PLizardStream; ip, iLowLimit, iHighLimit: PByte;
                                  longest: Integer; out matchPos, startPos: PByte): Integer;
var
  chainTable, hashTable: PUInt32;
  base, dictBase, dictEnd, lowPrefixPtr: PByte;
  dictLimit, lowLimit, maxDist, current, contentMask: UInt32;
  matchIndex, delta: UInt32;
  match: PByte;
  nbAttempts, LLdelta: Integer;
  mlt, back: Integer;
begin
  chainTable   := ctx^.chainTable;
  hashTable    := ctx^.hashTable;
  base         := ctx^.base;
  dictBase     := ctx^.dictBase;
  dictLimit    := ctx^.dictLimit;
  lowPrefixPtr := base + dictLimit;
  dictEnd      := dictBase + dictLimit;
  contentMask  := (UInt32(1) shl ctx^.params.contentLog) - 1;
  maxDist      := (UInt32(1) shl ctx^.params.windowLog) - 1;
  current      := UInt32(ip - base);
  if ctx^.lowLimit + maxDist >= current then
    lowLimit := ctx^.lowLimit
  else
    lowLimit := current - maxDist;
  nbAttempts := Integer(ctx^.params.searchNum);
  LLdelta    := Integer(ip - iLowLimit);
  matchPos   := nil;  startPos := ip;

  Lizard_Insert_HC(ctx, ip);
  matchIndex := hashTable[Lizard_hashPtr(ip, ctx^.params.hashLog, ctx^.params.searchLength)];

  while (matchIndex < current) and (matchIndex >= lowLimit) and (nbAttempts > 0) do begin
    Dec(nbAttempts);
    if matchIndex >= dictLimit then begin
      match := base + matchIndex;
      if (UInt32(PtrUInt(ip)-PtrUInt(match)) >= LIZARD_HC_MIN_OFFSET) and
         ((iLowLimit+longest)^ = (match-LLdelta+longest)^) and
         (MEM_read32(match) = MEM_read32(ip)) then begin
        mlt  := MINMATCH + Integer(Lizard_count(ip+MINMATCH, match+MINMATCH, iHighLimit));
        back := 0;
        while (ip+back-1 > iLowLimit) and (match+back-1 >= lowPrefixPtr) and
              ((ip+back-1)^ = (match+back-1)^) do Dec(back);
        mlt := mlt - back;
        if mlt > longest then begin
          longest  := mlt;
          matchPos := match + back;
          startPos := ip + back;
        end;
      end;
    end else begin
      match := dictBase + matchIndex;
      if (UInt32(PtrUInt(ip)-(PtrUInt(base)+matchIndex)) >= LIZARD_HC_MIN_OFFSET) and
         (UInt32(dictLimit-1-matchIndex) >= 3) and
         (MEM_read32(match) = MEM_read32(ip)) then begin
        mlt  := Integer(Lizard_count_2segments(ip+MINMATCH, match+MINMATCH, iHighLimit, dictEnd, lowPrefixPtr)) + MINMATCH;
        back := 0;
        while (ip+back-1 > iLowLimit) and (UInt32(matchIndex)-back >= lowLimit+1) and
              ((ip+back-1)^ = (match+back-1)^) do Dec(back);
        mlt := mlt - back;
        if mlt > longest then begin
          longest  := mlt;
          matchPos := base + matchIndex + back;
          startPos := ip + back;
        end;
      end;
    end;
    delta := chainTable[matchIndex and contentMask];
    if delta > matchIndex then Break;
    matchIndex := matchIndex - delta;
  end;
  Result := longest;
end;

const OPTIMAL_ML_LZ4 = ML_MASK_LZ4 - 1 + MINMATCH;   { 18 }

function Lizard_compress_hashChain(ctx: PLizardStream; ip, iend: PByte): Integer;
label _search2, _search3, _last_literals, _err;
var
  anchor, mfend, matchlimit: PByte;
  ml, ml2, ml3, ml0: Integer;
  ref, ref2, ref3, ref0: PByte;
  start2, start3, start0: PByte;
  dummy: PByte;
  newml, correction: Integer;
begin
  Result := 0;
  anchor     := ip;
  mfend    := iend - MFLIMIT;
  matchlimit := iend - LASTLITERALS;
  ref := nil; ref2 := nil; ref3 := nil;
  start2 := nil; start3 := nil;
  ref0 := nil; start0 := nil; ml0 := 0;
  Inc(ip);

  while ip < mfend do begin
    ml := Lizard_FindBestMatch_HC(ctx, ip, matchlimit, ref);
    if ml = 0 then begin Inc(ip); Continue; end;

    start0 := ip;  ref0 := ref;  ml0 := ml;

_search2:
    if ip + ml < mfend then
      ml2 := Lizard_GetWiderMatch_HC(ctx, ip+ml-2, ip+1, matchlimit, ml, ref2, start2)
    else
      ml2 := ml;

    if ml2 = ml then begin
      if Lizard_encodeSequence_LZ4(ctx, ip, anchor, ml, ref) then goto _err;
      Continue;
    end;

    if start0 < ip then
      if start2 < ip + ml0 then begin ip := start0; ref := ref0; ml := ml0; end;

    if (start2 - ip) < 3 then begin
      ml := ml2; ip := start2; ref := ref2; goto _search2;
    end;

_search3:
    if (start2 - ip) < OPTIMAL_ML_LZ4 then begin
      newml := ml;
      if newml > OPTIMAL_ML_LZ4 then newml := OPTIMAL_ML_LZ4;
      if ip + newml > start2 + ml2 - MINMATCH then
        newml := Integer(start2 - ip) + ml2 - MINMATCH;
      correction := newml - Integer(start2 - ip);
      if correction > 0 then begin
        Inc(start2, correction); Inc(ref2, correction); Dec(ml2, correction);
      end;
    end;

    if start2 + ml2 < mfend then
      ml3 := Lizard_GetWiderMatch_HC(ctx, start2+ml2-3, start2, matchlimit, ml2, ref3, start3)
    else
      ml3 := ml2;

    if ml3 = ml2 then begin
      if start2 < ip + ml then ml := Integer(start2 - ip);
      if Lizard_encodeSequence_LZ4(ctx, ip, anchor, ml, ref) then goto _err;
      ip := start2;
      if Lizard_encodeSequence_LZ4(ctx, ip, anchor, ml2, ref2) then goto _err;
      Continue;
    end;

    if start3 < ip + ml + 3 then begin
      if start3 >= ip + ml then begin
        if start2 < ip + ml then begin
          correction := Integer(ip + ml - start2);
          Inc(start2, correction); Inc(ref2, correction); Dec(ml2, correction);
          if ml2 < MINMATCH then begin start2 := start3; ref2 := ref3; ml2 := ml3; end;
        end;
        if Lizard_encodeSequence_LZ4(ctx, ip, anchor, ml, ref) then goto _err;
        ip := start3; ref := ref3; ml := ml3;
        start0 := start2; ref0 := ref2; ml0 := ml2;
        goto _search2;
      end;
      start2 := start3; ref2 := ref3; ml2 := ml3;
      goto _search3;
    end;

    if start2 < ip + ml then begin
      if Integer(start2 - ip) < ML_MASK_LZ4 then begin
        if ml > OPTIMAL_ML_LZ4 then ml := OPTIMAL_ML_LZ4;
        if ip + ml > start2 + ml2 - MINMATCH then
          ml := Integer(start2 - ip) + ml2 - MINMATCH;
        if ml < MINMATCH then begin
          if Lizard_encodeSequence_LZ4(ctx, ip, anchor, ml, ref) then goto _err;
          ip := start3; ref := ref3; ml := ml3;
          start0 := start2; ref0 := ref2; ml0 := ml2;
          goto _search2;
        end;
        correction := ml - Integer(start2 - ip);
        if correction > 0 then begin
          Inc(start2, correction); Inc(ref2, correction); Dec(ml2, correction);
        end;
      end else
        ml := Integer(start2 - ip);
    end;
    if Lizard_encodeSequence_LZ4(ctx, ip, anchor, ml, ref) then goto _err;
    ip := start2; ref := ref2; ml := ml2;
    start2 := start3; ref2 := ref3; ml2 := ml3;
    goto _search3;
  end;

_last_literals:
  ip := iend;
  if Lizard_encodeLastLiterals_LZ4(ctx, ip, anchor) then goto _err;
  Result := 1;  Exit;
_err:
  Result := 0;
end;

{ ---- compress dispatcher ---- }

function Lizard_compress_generic(ctx: PLizardStream; src, dst: PByte;
                                  srcSize, maxDstSize: Integer): Integer;
var
  ip, op, oend: PByte;
  inputSize, inputPart, res: Integer;
begin
  Result := 0;
  ip   := src;  op := dst;  oend := dst + maxDstSize;
  if op >= oend then Exit;
  op^ := Byte(ctx^.compressionLevel);  Inc(op);
  ctx^.endPtr := PByte(src) + srcSize;
  ctx^.srcBase := src;  ctx^.destBase := dst;
  inputSize := srcSize;
  while inputSize > 0 do begin
    if inputSize > LIZARD_BLOCK_SIZE then inputPart := LIZARD_BLOCK_SIZE
    else inputPart := inputSize;
    Lizard_initBlockState(ctx);
    ctx^.diffBase := ip;
    case ctx^.params.parserType of
      ptFastSmall: res := Lizard_compress_fast_internal(ctx, ip, ip+inputPart, LIZARD_HASHLOG_LZ4SM);
      ptFast:      res := Lizard_compress_fast_internal(ctx, ip, ip+inputPart, LIZARD_HASHLOG_LZ4);
      ptNoChain:   res := Lizard_compress_fast_internal(ctx, ip, ip+inputPart, LIZARD_HASHLOG_LZ4);
      ptHashChain: res := Lizard_compress_hashChain(ctx, ip, ip+inputPart);
    else res := 0;
    end;
    if res <= 0 then Exit;
    if Lizard_writeBlock(ctx, ip, inputPart, op, oend) then Exit;
    Inc(ip, inputPart);
    Dec(inputSize, inputPart);
  end;
  Result := Integer(op - dst);
end;

{ =========================================================
  Public compression API
  ========================================================= }

function Lizard_compressBound(inputSize: Integer): Integer;
begin
  if UInt32(inputSize) > UInt32(LIZARD_MAX_INPUT_SIZE) then Result := 0
  else Result := inputSize + 1 + 1 + ((inputSize div LIZARD_BLOCK_SIZE) + 1) * 4;
end;

function Lizard_compress(src: PByte; dst: PByte;
                         srcSize, maxDstSize, compressionLevel: Integer): Integer;
var
  level, stateSize: Integer;
  statePtr: PByte;
  ctx: PLizardStream;
begin
  Result   := 0;
  level    := Lizard_verifyLevel(compressionLevel);
  stateSize:= Lizard_sizeofState(level);
  GetMem(statePtr, stateSize);
  try
    ctx := PLizardStream(statePtr);
    Lizard_initStream(ctx, level);
    Lizard_initCtx(ctx, src);
    Result := Lizard_compress_generic(ctx, src, dst, srcSize, maxDstSize);
  finally
    FreeMem(statePtr, stateSize);
  end;
end;

{ =========================================================
  Decompressor
  ========================================================= }

function DecompressTypeForLevel(level: Integer): TDecompressType; inline;
begin
  if (level >= 10) and (level <= 19) then Result := dtLZ4
  else Result := dtLIZv1;
end;

{ ---- LZ4-codewords inner loop ---- }

function Lizard_decompress_LZ4(ctx: PLizard_dstream; dest: PByte; outputSize: Integer;
                                partialDecoding, targetOutputSize, dict: Integer;
                                lowPrefix, dictStart: PByte; dictSize: NativeUInt): Integer;
label _output_error;
var
  blockBase, iend: PByte;
  op, oend, oexit, cpy: PByte;
  lowLimit, dictEnd: PByte;
  token: Byte;
  length, offset: NativeUInt;
  match: PByte;
  checkOffset: Boolean;
  copySize, restSize: NativeUInt;
  endOfMatch, copyFrom: PByte;
begin
  blockBase   := ctx^.flagsPtr;
  iend        := ctx^.literalsEnd;
  op          := dest;
  oend        := dest + outputSize;
  oexit       := dest + targetOutputSize;
  lowLimit    := lowPrefix - dictSize;
  if dictStart <> nil then dictEnd := dictStart + dictSize else dictEnd := nil;
  checkOffset := (dictSize < LIZARD_DICT_SIZE);

  if outputSize = 0 then begin
    if (ctx^.flagsEnd - ctx^.flagsPtr = 1) and (ctx^.flagsPtr^ = 0) then Result := 0
    else Result := -1;
    Exit;
  end;

  while ctx^.flagsPtr < ctx^.flagsEnd do begin
    token := ctx^.flagsPtr^;  Inc(ctx^.flagsPtr);

    { literal length }
    length := token and RUN_MASK_LZ4;
    if length = RUN_MASK_LZ4 then begin
      if ctx^.literalsPtr > iend - 5 then goto _output_error;
      length := ctx^.literalsPtr^;
      if length >= 254 then begin
        if length = 254 then begin
          length := MEM_readLE16(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,2);
        end else begin
          length := MEM_readLE24(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,3);
        end;
      end;
      Inc(length, RUN_MASK_LZ4);
      Inc(ctx^.literalsPtr);
    end;

    { copy literals }
    cpy := op + length;
    if (cpy > oend - WILDCOPYLENGTH) or
       (ctx^.literalsPtr + length > iend - WILDCOPYLENGTH - 2) then
      goto _output_error;
    Lizard_wildCopy16(op, ctx^.literalsPtr, cpy);
    op := cpy;  Inc(ctx^.literalsPtr, length);
    if (partialDecoding <> 0) and (op >= oexit) then begin Result := Integer(op-dest); Exit; end;

    { offset }
    offset := MEM_readLE16(ctx^.literalsPtr);  Inc(ctx^.literalsPtr, 2);
    match  := op - offset;
    if checkOffset and (PtrUInt(offset) > PtrUInt(op) - PtrUInt(lowLimit)) then
      goto _output_error;

    { match length }
    length := token shr RUN_BITS_LZ4;
    if length = ML_MASK_LZ4 then begin
      if ctx^.literalsPtr > iend - 5 then goto _output_error;
      length := ctx^.literalsPtr^;
      if length >= 254 then begin
        if length = 254 then begin
          length := MEM_readLE16(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,2);
        end else begin
          length := MEM_readLE24(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,3);
        end;
      end;
      Inc(length, ML_MASK_LZ4);
      Inc(ctx^.literalsPtr);
    end;
    Inc(length, MINMATCH);

    { external dict }
    if (dict = usingExtDict) and (match < lowPrefix) then begin
      if op + length > oend - WILDCOPYLENGTH then goto _output_error;
      if length <= NativeUInt(lowPrefix - match) then begin
        Move((dictEnd - NativeUInt(lowPrefix-match))^, op^, length);  Inc(op, length);
      end else begin
        copySize := NativeUInt(lowPrefix - match);
        restSize := length - copySize;
        Move((dictEnd - copySize)^, op^, copySize);  Inc(op, copySize);
        if restSize > NativeUInt(op - lowPrefix) then begin
          endOfMatch := op + restSize;  copyFrom := lowPrefix;
          while op < endOfMatch do begin op^ := copyFrom^; Inc(op); Inc(copyFrom); end;
        end else begin Move(lowPrefix^, op^, restSize);  Inc(op, restSize); end;
      end;
      Continue;
    end;

    { copy match }
    cpy := op + length;
    if cpy > oend - WILDCOPYLENGTH then goto _output_error;
    MEM_copy8(op, match);  MEM_copy8(op+8, match+8);
    if length > 16 then Lizard_wildCopy16(op+16, match+16, cpy);
    op := cpy;
    if (partialDecoding <> 0) and (op >= oexit) then begin Result := Integer(op-dest); Exit; end;
  end;

  { last literals }
  length := NativeUInt(ctx^.literalsEnd - ctx^.literalsPtr);
  cpy    := op + length;
  if (NativeInt(length) < 0) or (ctx^.literalsPtr+length <> iend) or (cpy > oend) then
    goto _output_error;
  Move(ctx^.literalsPtr^, op^, length);
  op := cpy;
  Result := Integer(op - dest);  Exit;

_output_error:
  Result := -Integer(ctx^.flagsPtr - blockBase) - 1;
end;

{ ---- LIZv1-codewords inner loop ---- }

function Lizard_decompress_LIZv1(ctx: PLizard_dstream; dest: PByte; outputSize: Integer;
                                  partialDecoding, targetOutputSize, dict: Integer;
                                  lowPrefix, dictStart: PByte; dictSize: NativeUInt): Integer;
label _output_error;
var
  blockBase, iend: PByte;
  op, oend, oexit, cpy: PByte;
  lowLimit, dictEnd: PByte;
  token: Byte;
  length: NativeUInt;
  last_off: IntPtr;
  match: PByte;
  checkOffset: Boolean;
  copySize, restSize: NativeUInt;
  endOfMatch, copyFrom: PByte;
  newOff: IntPtr;
  notRep: NativeUInt;
begin
  blockBase   := ctx^.flagsPtr;
  iend        := ctx^.literalsEnd;
  op          := dest;
  oend        := dest + outputSize;
  oexit       := dest + targetOutputSize;
  lowLimit    := lowPrefix - dictSize;
  dictEnd     := dictStart + dictSize;
  checkOffset := (dictSize < LIZARD_DICT_SIZE);
  last_off    := ctx^.last_off;

  if outputSize = 0 then begin
    if (ctx^.flagsEnd - ctx^.flagsPtr = 1) and (ctx^.flagsPtr^ = 0) then Result := 0
    else Result := -1;
    Exit;
  end;

  while ctx^.flagsPtr < ctx^.flagsEnd do begin
    if (partialDecoding <> 0) and (op >= oexit) then begin Result := Integer(op-dest); Exit; end;
    token := ctx^.flagsPtr^;  Inc(ctx^.flagsPtr);

    if token >= 32 then begin
      { 16-bit offset or rep-match }
      length := token and MAX_SHORT_LITLEN;
      if length = MAX_SHORT_LITLEN then begin
        if ctx^.literalsPtr >= iend then goto _output_error;
        length := ctx^.literalsPtr^;  Inc(ctx^.literalsPtr);
        if length >= 254 then begin
          if length = 254 then begin
            if ctx^.literalsPtr+1 >= iend then goto _output_error;
            length := MEM_readLE16(ctx^.literalsPtr);  Inc(ctx^.literalsPtr,2);
          end else begin
            if ctx^.literalsPtr+2 >= iend then goto _output_error;
            length := MEM_readLE24(ctx^.literalsPtr);  Inc(ctx^.literalsPtr,3);
          end;
        end;
        Inc(length, MAX_SHORT_LITLEN);
      end;

      { copy literals }
      cpy := op + length;
      if (cpy > oend - WILDCOPYLENGTH) or (ctx^.literalsPtr+length > iend-WILDCOPYLENGTH) then
        goto _output_error;
      Lizard_wildCopy16(op, ctx^.literalsPtr, cpy);
      op := cpy;  Inc(ctx^.literalsPtr, length);

      { branchless offset: rep or new 16-bit offset }
      if ctx^.offset16End - ctx^.offset16Ptr >= 2 then begin
        newOff := -IntPtr(MEM_readLE16(ctx^.offset16Ptr));
        notRep := NativeUInt(token shr ML_RUN_BITS) - 1;
        last_off := last_off xor (IntPtr(notRep) and (last_off xor newOff));
        ctx^.offset16Ptr := PByte(PtrUInt(ctx^.offset16Ptr) + (notRep and 2));
      end;

      { match length }
      length := (token shr RUN_BITS_LIZv1) and MAX_SHORT_MATCHLEN;
      if length = MAX_SHORT_MATCHLEN then begin
        if ctx^.literalsPtr >= iend then goto _output_error;
        length := ctx^.literalsPtr^;
        if length >= 254 then begin
          if length = 254 then begin
            length := MEM_readLE16(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,2);
          end else begin
            length := MEM_readLE24(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,3);
          end;
        end;
        Inc(length, MAX_SHORT_MATCHLEN);
        Inc(ctx^.literalsPtr);
      end;

    end else if token < LIZARD_LAST_LONG_OFF then begin
      { 24-bit offset, match length = token + MM_LONGOFF (16..46) }
      if ctx^.offset24Ptr > ctx^.offset24End - 3 then goto _output_error;
      length  := token + MM_LONGOFF;
      last_off := -IntPtr(MEM_readLE24(ctx^.offset24Ptr));
      Inc(ctx^.offset24Ptr, 3);

    end else begin
      { token = 31: 24-bit offset, extended match length }
      if ctx^.literalsPtr >= iend then goto _output_error;
      length := ctx^.literalsPtr^;
      if length >= 254 then begin
        if length = 254 then begin
          length := MEM_readLE16(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,2);
        end else begin
          length := MEM_readLE24(ctx^.literalsPtr+1); Inc(ctx^.literalsPtr,3);
        end;
      end;
      Inc(ctx^.literalsPtr);
      Inc(length, LIZARD_LAST_LONG_OFF + MM_LONGOFF);
      if ctx^.offset24Ptr > ctx^.offset24End - 3 then goto _output_error;
      last_off := -IntPtr(MEM_readLE24(ctx^.offset24Ptr));
      Inc(ctx^.offset24Ptr, 3);
    end;

    match := op + last_off;
    if checkOffset and
       ((PtrUInt(-last_off) > PtrUInt(op)) or (match < lowLimit)) then
      goto _output_error;

    if (dict = usingExtDict) and (match < lowPrefix) then begin
      if op + length > oend - WILDCOPYLENGTH then goto _output_error;
      if length <= NativeUInt(lowPrefix - match) then begin
        Move((dictEnd - NativeUInt(lowPrefix-match))^, op^, length);  Inc(op, length);
      end else begin
        copySize := NativeUInt(lowPrefix - match);
        restSize := length - copySize;
        Move((dictEnd - copySize)^, op^, copySize);  Inc(op, copySize);
        if restSize > NativeUInt(op - lowPrefix) then begin
          endOfMatch := op + restSize;  copyFrom := lowPrefix;
          while op < endOfMatch do begin op^ := copyFrom^; Inc(op); Inc(copyFrom); end;
        end else begin Move(lowPrefix^, op^, restSize);  Inc(op, restSize); end;
      end;
      Continue;
    end;

    cpy := op + length;
    if cpy > oend - WILDCOPYLENGTH then goto _output_error;
    MEM_copy8(op, match);  MEM_copy8(op+8, match+8);
    if length > 16 then Lizard_wildCopy16(op+16, match+16, cpy);
    op := cpy;
  end;

  length := NativeUInt(ctx^.literalsEnd - ctx^.literalsPtr);
  cpy    := op + length;
  if (NativeInt(length) < 0) or (ctx^.literalsPtr+length <> iend) or (cpy > oend) then
    goto _output_error;
  Move(ctx^.literalsPtr^, op^, length);
  ctx^.last_off := last_off;
  op := cpy;
  Result := Integer(op - dest);  Exit;

_output_error:
  Result := -Integer(ctx^.flagsPtr - blockBase) - 1;
end;

{ ---- read an uncompressed sub-stream ---- }

function ReadStream(var ip: PByte; iend: PByte;
                    out sPtr, sEnd: PByte): Boolean;
var slen: UInt32;
begin
  if ip > iend - 3 then begin Result := False; Exit; end;
  slen := MEM_readLE24(ip);
  sPtr := ip + 3;
  sEnd := sPtr + slen;
  if (sEnd < sPtr) or (sEnd > iend) then begin Result := False; Exit; end;
  ip := sEnd;
  Result := True;
end;

{ ---- generic decompressor ---- }

function Lizard_decompress_generic(source, dest: PByte;
                                    inputSize, outputSize,
                                    partialDecoding, targetOutputSize, dict: Integer;
                                    lowPrefix, dictStart: PByte;
                                    dictSize: NativeUInt): Integer;
var
  ip, iend: PByte;
  op, oexit: PByte;
  comprLevel: Integer;
  decompType: TDecompressType;
  dctx: TLizard_dstream;
  decompBuf: PByte;
  blockFlags: Byte;
  blockLen: UInt32;
  blockRes: Integer;
  dummy1, dummy2: PByte;
begin
  Result := -1;
  if inputSize < 1 then Exit;

  ip   := source;
  iend := source + inputSize;
  op   := dest;
  oexit:= dest + targetOutputSize;

  comprLevel := ip^;  Inc(ip);
  if (comprLevel < LIZARD_MIN_CLEVEL) or (comprLevel > 49) then Exit;
  decompType := DecompressTypeForLevel(comprLevel);

  GetMem(decompBuf, 4 * LIZARD_BLOCK_SIZE);
  try
    while ip < iend do begin
      blockFlags := ip^;  Inc(ip);

      if blockFlags = LIZARD_FLAG_UNCOMPRESSED then begin
        if ip > iend - 3 then Exit;
        blockLen := MEM_readLE24(ip);  Inc(ip, 3);
        if (ip + blockLen > iend) or (op + PtrInt(blockLen) > dest + outputSize) then Exit;
        Move(ip^, op^, blockLen);
        Inc(ip, blockLen);  Inc(op, blockLen);
        if (partialDecoding <> 0) and (op >= oexit) then Break;
        Continue;
      end;

      if (blockFlags and LIZARD_FLAG_LEN) <> 0 then Exit;

      { any Huffman flag = not supported }
      if (blockFlags and (LIZARD_FLAG_LITERALS or LIZARD_FLAG_FLAGS or
                          LIZARD_FLAG_OFFSET16 or LIZARD_FLAG_OFFSET24)) <> 0 then Exit;

      { len stream (always 0 bytes) }
      if not ReadStream(ip, iend, dctx.lenPtr, dctx.lenEnd) then Exit;

      { offset16 stream }
      if not ReadStream(ip, iend, dctx.offset16Ptr, dctx.offset16End) then Exit;

      { offset24 stream }
      if not ReadStream(ip, iend, dctx.offset24Ptr, dctx.offset24End) then Exit;

      { flags stream }
      if not ReadStream(ip, iend, dctx.flagsPtr, dctx.flagsEnd) then Exit;

      { literals stream }
      if not ReadStream(ip, iend, dctx.literalsPtr, dctx.literalsEnd) then Exit;

      if ip > iend then Exit;
      dctx.last_off := -LIZARD_INIT_LAST_OFFSET;

      if decompType = dtLZ4 then
        blockRes := Lizard_decompress_LZ4(@dctx, op, outputSize, partialDecoding,
                      targetOutputSize, dict, lowPrefix, dictStart, dictSize)
      else
        blockRes := Lizard_decompress_LIZv1(@dctx, op, outputSize, partialDecoding,
                      targetOutputSize, dict, lowPrefix, dictStart, dictSize);

      if blockRes <= 0 then begin Result := blockRes; Exit; end;
      Inc(op, blockRes);
      Dec(outputSize, blockRes);
      if (partialDecoding <> 0) and (op >= oexit) then Break;
    end;
  finally
    FreeMem(decompBuf, 4 * LIZARD_BLOCK_SIZE);
  end;

  Result := Integer(op - dest);
end;

{ =========================================================
  Public decompression API
  ========================================================= }

function Lizard_decompress_safe(source: PByte; dest: PByte;
                                compressedSize, maxDecompressedSize: Integer): Integer;
begin
  Result := Lizard_decompress_generic(source, dest, compressedSize,
              maxDecompressedSize, 0, 0, noDict, dest, nil, 0);
end;

function Lizard_decompress_safe_partial(source: PByte; dest: PByte;
                                        compressedSize, targetOutputSize,
                                        maxDecompressedSize: Integer): Integer;
begin
  Result := Lizard_decompress_generic(source, dest, compressedSize,
              maxDecompressedSize, 1, targetOutputSize, noDict, dest, nil, 0);
end;

end.
