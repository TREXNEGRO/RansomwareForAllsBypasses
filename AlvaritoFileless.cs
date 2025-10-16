using System;
using System.Buffers;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

class Program
{
    // ---------- Constants ----------
    private static readonly string DefaultFolder = @"C:\TEST";
    private const int FileVersion = 4;
    private const byte AlgoChunkedGcm = 3;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("EBOX");

    private const int SaltSize = 16;         // 128-bit
    private const int GcmNonceSize = 12;     // 96-bit
    private const int GcmTagSize = 16;       // 128-bit
    private const int DefaultChunkSize = 4 * 1024 * 1024; // 4 MiB
    private const int Pbkdf2Iterations = 600_000;

    // TLV types
    private const byte TLV_OrigLen = 0x01;       // 8 bytes (Int64)
    private const byte TLV_MTimeUtcTicks = 0x02; // 8 bytes (Int64)
    private const byte TLV_CTimeUtcTicks = 0x03; // 8 bytes (Int64)
    private const byte TLV_UserAad = 0x04;       // N bytes (UTF8)

    // Recipient types
    private const byte REC_Passphrase = 0x01;    // Wrap DEK with KEK derived from passphrase
    private const byte REC_DpapiUser = 0x02;     // Wrap DEK with DPAPI CurrentUser
    private const byte REC_DpapiMachine = 0x03;  // Wrap DEK with DPAPI LocalMachine

    // KDF ids
    private const byte KDF_PBKDF2 = 0x01;
    private const byte KDF_ARGON2ID = 0x02; // via reflection if available

    // ---------- CLI Options ----------
    private class Options
    {
        public string Folder = DefaultFolder;
        public int ChunkSize = DefaultChunkSize;
        public int Workers = Math.Max(1, Environment.ProcessorCount / 2); // per-file workers
        public int FileParallelism = 1; // number of files processed in parallel
        public bool DeletePlaintext = false;
        public bool Yes = false;
        public string Kdf = "pbkdf2"; // pbkdf2 | argon2id
        public HashSet<string> IncludeExt = new();
        public HashSet<string> ExcludeExt = new();
        public string UserAad = string.Empty;
        public bool AddDpapiUser = false;
        public bool AddDpapiMachine = false;

        // fileless modes
        public string? FilelessEncPath = null; // encrypt this file to stdout
        public bool FilelessDec = false;       // decrypt from stdin
        public string? FilelessDecOut = null;  // optional output path for fileless dec
    }

    static void Main(string[] args)
    {
        var opt = ParseArgs(args);

        // FILELESS ENCRYPT: read from file, write to STDOUT
        if (!string.IsNullOrEmpty(opt.FilelessEncPath))
        {
            if (!File.Exists(opt.FilelessEncPath)) { Console.Error.WriteLine("Input no existe"); return; }
            Console.Error.Write("Contraseña (Enter para vacía y solo DPAPI): ");
            string pass = ReadPasswordAllowEmpty(); Console.Error.WriteLine();

            EncryptSingleFileToStream(opt.FilelessEncPath!, Console.OpenStandardOutput(), opt, pass, fileless: true);
            return;
        }

        // FILELESS DECRYPT: read EBOX from STDIN, write plaintext to STDOUT or file
        if (opt.FilelessDec)
        {
            Console.Error.Write("Contraseña (Enter para intentar DPAPI): ");
            string decPass = ReadPasswordAllowEmpty(); Console.Error.WriteLine();

            using var stdin = Console.OpenStandardInput();
            if (opt.FilelessDecOut is null)
            {
                using var stdout = Console.OpenStandardOutput();
                DecryptStreamToStream(stdin, stdout, decPass);
            }
            else
            {
                DecryptStreamToFile(stdin, opt.FilelessDecOut, decPass);
            }
            return;
        }

        // DIRECTORY MODE
        if (!Directory.Exists(opt.Folder)) { Console.WriteLine($"No existe la carpeta: {opt.Folder}"); return; }

        Console.Write("Contraseña (Enter para vacía y solo DPAPI): ");
        string pass1 = ReadPasswordAllowEmpty();
        string pass2 = pass1.Length > 0 ? PromptRepeat(pass1) : string.Empty;

        var files = Directory.EnumerateFiles(opt.Folder, "*", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
            .Where(IsProcessableFile)
            .Where(f => FilterByExt(f, opt))
            .ToList();
        if (files.Count == 0) { Console.WriteLine("No hay archivos para cifrar."); return; }

        if (opt.DeletePlaintext && !opt.Yes)
        {
            Console.Write("Confirmar borrado de originales tras cifrar (escribe 'SI'): ");
            var conf = Console.ReadLine();
            if (!string.Equals(conf, "SI", StringComparison.OrdinalIgnoreCase))
            { Console.WriteLine("Abortado."); return; }
        }

        Console.WriteLine($"Archivos: {files.Count} | Chunk: {opt.ChunkSize / (1024 * 1024)} MiB | Workers/archivo: {opt.Workers} | Paralelismo de archivos: {opt.FileParallelism}
");

        var queue = new ConcurrentQueue<string>(files);
        int ok = 0, err = 0, del = 0;
        Parallel.For(0, Math.Max(1, opt.FileParallelism), _ =>
        {
            while (queue.TryDequeue(out var input))
            {
                try
                {
                    string output = input + ".enc";
                    string tmp = output + ".tmp";
                    EncryptSingleFileToStream(input, new FileStream(tmp, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 1 << 20, FileOptions.SequentialScan), opt, pass1, fileless: false, outputPathForPrealloc: output);
                    ReplaceFile(tmp, output);
                    if (opt.DeletePlaintext) { TrySecureDelete(input); System.Threading.Interlocked.Increment(ref del); }
                    Console.WriteLine($"[OK] {Path.GetFileName(input)} -> {Path.GetFileName(output)}");
                    System.Threading.Interlocked.Increment(ref ok);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERR] {Path.GetFileName(input)}: {ex.Message}");
                    System.Threading.Interlocked.Increment(ref err);
                }
            }
        });

        Console.WriteLine($"
Completado.Éxitos: { ok} | Errores: { err} | Borrados: { del}
        ");
    }

    // ---------- Core: Encrypt single file to target stream with pipeline ----------
    private static void EncryptSingleFileToStream(string inputPath, Stream targetStream, Options opt, string passphrase, bool fileless, string? outputPathForPrealloc = null)
    {
        using var outFs = targetStream; // owns stream
        var info = new FileInfo(inputPath);

        // 1) Per-file DEK
        byte[] dek = RandomBytes(32);

        // 2) TLV meta
        byte[] tlvMeta = BuildTlvMeta(info, opt.UserAad);

        // 3) Recipients (pass + DPAPI)
        byte[] recipients = BuildRecipients(dek, passphrase, opt.Kdf, opt.AddDpapiUser, opt.AddDpapiMachine);

        // 4) Stream params
        byte[] baseNonce = RandomBytes(GcmNonceSize);
        long totalChunks = ComputeTotalChunks(info.Length, opt.ChunkSize);

        // 5) Header and headerHash (AAD)
        byte[] header = BuildHeader(tlvMeta, recipients, opt.ChunkSize, baseNonce, totalChunks);
        byte[] headerHash = SHA256(header);

        // 6) Pre-allocate file size if writing to a FileStream (and not fileless)
        if (!fileless && outFs is FileStream ofs)
        {
            long headerLen = header.Length;
            long totalTags = totalChunks * GcmTagSize;
            long totalSize = headerLen + info.Length + totalTags;
            ofs.SetLength(totalSize);
        }

        // 7) Write header
        outFs.Write(header, 0, header.Length);

        // 8) Build pipeline: read -> encrypt (N) -> write (ordered)
        var readChan = Channel.CreateBounded<PlainChunk>(new BoundedChannelOptions(Math.Max(2, opt.Workers * 2)) { FullMode = BoundedChannelFullMode.Wait });
        var encChan = Channel.CreateBounded<EncChunk>(new BoundedChannelOptions(Math.Max(2, opt.Workers * 2)) { FullMode = BoundedChannelFullMode.Wait });

        var readerTask = Task.Run(() => ReaderLoop(inputPath, readChan.Writer, opt.ChunkSize));

        var workerTasks = new List<Task>();
        for (int w = 0; w < opt.Workers; w++)
        {
            workerTasks.Add(Task.Run(() => EncryptLoop(readChan.Reader, encChan.Writer, dek, headerHash, baseNonce, opt.ChunkSize)));
        }

        var writerTask = Task.Run(() => WriterLoop(encChan.Reader, outFs));

        Task.WaitAll(workerTasks.ToArray());
        encChan.Writer.Complete();
        writerTask.Wait();

        Array.Clear(dek, 0, dek.Length);
        outFs.Flush();
    }

    // ---------- Reader: fills channel with plaintext chunks ----------
    private struct PlainChunk { public long Index; public int Length; public byte[] Buffer; }
    private static void ReaderLoop(string inputPath, ChannelWriter<PlainChunk> writer, int chunkSize)
    {
        var pool = ArrayPool<byte>.Shared;
        try
        {
            using var inFs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
            long idx = 0;
            while (true)
            {
                byte[] buf = pool.Rent(chunkSize);
                int r = ReadExact(inFs, buf, chunkSize);
                if (r == 0)
                {
                    pool.Return(buf);
                    break;
                }
                writer.WriteAsync(new PlainChunk { Index = idx++, Length = r, Buffer = buf }).AsTask().Wait();
                if (r < chunkSize) break;
            }
        }
        finally
        {
            writer.Complete();
        }
    }

    // ---------- Encrypt workers: consume plaintext, produce ciphertext+tag ----------
    private struct EncChunk { public long Index; public int Length; public byte[] Cipher; public byte[] Tag; public byte[] PlainBuf; }
    private static void EncryptLoop(ChannelReader<PlainChunk> reader, ChannelWriter<EncChunk> writer, byte[] dek, byte[] headerHash, byte[] baseNonce, int chunkSize)
    {
        var pool = ArrayPool<byte>.Shared;
        using var gcm = new AesGcm(dek);
        byte[] aad = new byte[headerHash.Length + sizeof(long)];
        Buffer.BlockCopy(headerHash, 0, aad, 0, headerHash.Length);
        try
        {
            while (reader.WaitToReadAsync().AsTask().Result)
            {
                while (reader.TryRead(out var pc))
                {
                    byte[] cipher = pool.Rent(pc.Length);
                    byte[] tag = pool.Rent(GcmTagSize);
                    byte[] nonce = DeriveNonce(baseNonce, pc.Index);
                    WriteInt64LE(aad, headerHash.Length, pc.Index);
                    gcm.Encrypt(nonce, pc.Buffer.AsSpan(0, pc.Length), cipher.AsSpan(0, pc.Length), tag.AsSpan(0, GcmTagSize), aad);

                    writer.WriteAsync(new EncChunk { Index = pc.Index, Length = pc.Length, Cipher = cipher, Tag = tag, PlainBuf = pc.Buffer }).AsTask().Wait();
                }
            }
        }
        finally
        {
            writer.TryComplete();
        }
    }

    // ---------- Writer: preserves order and writes to output, returning buffers to pool ----------
    private static void WriterLoop(ChannelReader<EncChunk> reader, Stream outFs)
    {
        var pool = ArrayPool<byte>.Shared;
        long expect = 0;
        var pending = new SortedDictionary<long, EncChunk>();

        void FlushChunk(ref EncChunk ec)
        {
            outFs.Write(ec.Cipher, 0, ec.Length);
            outFs.Write(ec.Tag, 0, GcmTagSize);
            pool.Return(ec.Cipher);
            pool.Return(ec.Tag);
            pool.Return(ec.PlainBuf);
        }

        foreach (var ec in reader.ReadAllAsync().ToEnumerable())
        {
            if (ec.Index == expect)
            {
                var curr = ec; FlushChunk(ref curr); expect++;
                while (pending.TryGetValue(expect, out var nxt))
                {
                    pending.Remove(expect);
                    FlushChunk(ref nxt); expect++;
                }
            }
            else
            {
                pending[ec.Index] = ec;
            }
        }

        // Flush any stragglers (shouldn't happen if pipeline closed properly)
        while (pending.TryGetValue(expect, out var nxt2))
        {
            pending.Remove(expect);
            FlushChunk(ref nxt2); expect++;
        }
    }

    // ---------- Decrypt from stream to stream (fileless compatible) ----------
    private class RestoredMeta { public long? MTimeUtcTicks; public long? CTimeUtcTicks; public long? OrigLen; }

    private static void DecryptStreamToStream(Stream inStream, Stream outStream, string passphrase)
    {
        using var br = new BinaryReader(inStream, Encoding.UTF8, leaveOpen: true);
        // Header
        if (!br.ReadBytes(Magic.Length).SequenceEqual(Magic)) throw new InvalidDataException("MAGIC inválido");
        int ver = br.ReadByte(); if (ver != FileVersion) throw new InvalidDataException($"Versión no soportada: {ver}");
        int algo = br.ReadByte(); if (algo != AlgoChunkedGcm) throw new InvalidDataException($"Algoritmo no soportado: {algo}");

        int tlvLen = br.ReadInt32(); if (tlvLen < 0 || tlvLen > 10_000_000) throw new InvalidDataException("TLVLen inválido");
        byte[] tlv = br.ReadBytes(tlvLen);
        var meta = ParseTlv(tlv);

        int recLen = br.ReadInt32(); if (recLen < 0 || recLen > 10_000_000) throw new InvalidDataException("RecipientsLen inválido");
        byte[] recipients = br.ReadBytes(recLen);

        int chunkSize = br.ReadInt32(); if (chunkSize <= 0 || chunkSize > (1 << 26)) throw new InvalidDataException("ChunkSize inválido");
        byte[] baseNonce = br.ReadBytes(GcmNonceSize);
        long totalChunks = br.ReadInt64(); if (totalChunks <= 0) throw new InvalidDataException("TotalChunks inválido");
        int reserved = br.ReadInt32(); // ignore

        // Rebuild header for AAD
        byte[] header = BuildHeader(tlv, recipients, chunkSize, baseNonce, totalChunks);
        byte[] headerHash = SHA256(header);

        // Unwrap DEK
        byte[] dek = UnwrapDek(recipients, passphrase);

        using var gcm = new AesGcm(dek);
        var pool = ArrayPool<byte>.Shared;

        byte[] aad = new byte[headerHash.Length + sizeof(long)];
        Buffer.BlockCopy(headerHash, 0, aad, 0, headerHash.Length);

        long remaining = meta.OrigLen ?? throw new InvalidDataException("TLV sin longitud original");
        for (long idx = 0; idx < totalChunks; idx++)
        {
            int thisLen = (int)Math.Min(chunkSize, remaining > 0 ? remaining : 0);
            byte[] cipher = pool.Rent(thisLen);
            int readCipher = ReadExact(inStream, cipher, thisLen);
            if (readCipher != thisLen) throw new EndOfStreamException();

            byte[] tag = pool.Rent(GcmTagSize);
            int readTag = ReadExact(inStream, tag, GcmTagSize);
            if (readTag != GcmTagSize) throw new EndOfStreamException();

            byte[] nonce = DeriveNonce(baseNonce, idx);
            WriteInt64LE(aad, headerHash.Length, idx);

            byte[] plain = pool.Rent(thisLen);
            gcm.Decrypt(nonce, cipher.AsSpan(0, thisLen), tag.AsSpan(0, GcmTagSize), plain.AsSpan(0, thisLen), aad);
            if (thisLen > 0) outStream.Write(plain, 0, thisLen);

            pool.Return(cipher); pool.Return(tag); pool.Return(plain);
            remaining -= thisLen;
        }
        Array.Clear(dek, 0, dek.Length);
        outStream.Flush();
    }

    private static void DecryptStreamToFile(Stream inStream, string outputPath, string passphrase)
    {
        using var temp = new FileStream(outputPath + ".tmp", FileMode.Create, FileAccess.ReadWrite, FileShare.None, 1 << 20, FileOptions.SequentialScan);
        DecryptStreamToStream(inStream, temp, passphrase);
        temp.Flush(true);
        temp.Close();
        ReplaceFile(outputPath + ".tmp", outputPath);
    }

    // ---------- Header & helpers ----------
    private static byte[] BuildHeader(byte[] tlv, byte[] recipients, int chunkSize, byte[] baseNonce, long totalChunks)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write(Magic);                  // 4
        bw.Write((byte)FileVersion);      // 1
        bw.Write((byte)AlgoChunkedGcm);   // 1
        bw.Write(tlv.Length);             // 4
        bw.Write(tlv);
        bw.Write(recipients.Length);      // 4
        bw.Write(recipients);
        bw.Write(chunkSize);              // 4
        bw.Write(baseNonce);              // 12
        bw.Write(totalChunks);            // 8
        bw.Write(0);                      // 4 reserved
        bw.Flush();
        return ms.ToArray();
    }

    private class ParsedMeta
    {
        public long? OrigLen;
        public long? MTimeUtcTicks;
        public long? CTimeUtcTicks;
        public string? UserAad;
    }

    private static ParsedMeta ParseTlv(byte[] tlv)
    {
        var meta = new ParsedMeta();
        int i = 0;
        while (i + 3 <= tlv.Length)
        {
            byte t = tlv[i++];
            int len = BitConverter.ToUInt16(tlv, i); i += 2;
            if (len < 0 || i + len > tlv.Length) break;
            switch (t)
            {
                case TLV_OrigLen: if (len == 8) meta.OrigLen = BitConverter.ToInt64(tlv, i); break;
                case TLV_MTimeUtcTicks: if (len == 8) meta.MTimeUtcTicks = BitConverter.ToInt64(tlv, i); break;
                case TLV_CTimeUtcTicks: if (len == 8) meta.CTimeUtcTicks = BitConverter.ToInt64(tlv, i); break;
                case TLV_UserAad: meta.UserAad = Encoding.UTF8.GetString(tlv, i, len); break;
                default: break;
            }
            i += len;
        }
        return meta;
    }

    private static byte[] BuildTlvMeta(FileInfo fi, string userAad)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        void TLV(byte t, byte[] payload)
        {
            bw.Write(t);
            bw.Write((ushort)payload.Length);
            bw.Write(payload);
        }
        TLV(TLV_OrigLen, BitConverter.GetBytes(fi.Length));
        TLV(TLV_MTimeUtcTicks, BitConverter.GetBytes(fi.LastWriteTimeUtc.Ticks));
        TLV(TLV_CTimeUtcTicks, BitConverter.GetBytes(fi.CreationTimeUtc.Ticks));
        if (!string.IsNullOrEmpty(userAad)) TLV(TLV_UserAad, Encoding.UTF8.GetBytes(userAad));
        bw.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildRecipients(byte[] dek, string passphrase, string kdfName, bool addDpapiUser, bool addDpapiMachine)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        if (!string.IsNullOrEmpty(passphrase))
        {
            byte kdfId = kdfName.Equals("argon2id", StringComparison.OrdinalIgnoreCase) ? KDF_ARGON2ID : KDF_PBKDF2;
            byte[] salt = RandomBytes(SaltSize);
            byte[] kek = DeriveKey(passphrase, salt, 32, kdfName);
            byte[] nonce = RandomBytes(GcmNonceSize);
            byte[] wrapped = new byte[dek.Length];
            byte[] tag = new byte[GcmTagSize];
            using (var gcm = new AesGcm(kek)) gcm.Encrypt(nonce, dek, wrapped, tag);

            using var rec = new MemoryStream();
            using (var wr = new BinaryWriter(rec))
            {
                wr.Write((byte)kdfId);                    // 1
                wr.Write(Pbkdf2Iterations);               // 4 (PBKDF2 iter; ignored for Argon2id)
                wr.Write(salt);                           // 16
                wr.Write(nonce);                          // 12
                wr.Write(wrapped);                        // 32
                wr.Write(tag);                            // 16
            }
            WriteRecipient(bw, REC_Passphrase, rec.ToArray());
            Array.Clear(kek, 0, kek.Length);
        }

        if (addDpapiUser || addDpapiMachine)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI solo disponible en Windows");
            if (addDpapiUser)
            {
                var blob = ProtectedData.Protect(dek, null, DataProtectionScope.CurrentUser);
                WriteRecipient(bw, REC_DpapiUser, BuildDpapiPayload(blob, 1));
            }
            if (addDpapiMachine)
            {
                var blob = ProtectedData.Protect(dek, null, DataProtectionScope.LocalMachine);
                WriteRecipient(bw, REC_DpapiMachine, BuildDpapiPayload(blob, 2));
            }
        }

        bw.Flush();
        return ms.ToArray();
    }

    private static void WriteRecipient(BinaryWriter bw, byte type, byte[] payload)
    {
        bw.Write(type);
        bw.Write(payload.Length);
        bw.Write(payload);
    }

    private static byte[] BuildDpapiPayload(byte[] blob, byte scope)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write(scope);            // 1: user, 2: machine
        bw.Write(blob.Length);      // 4
        bw.Write(blob);
        bw.Flush();
        return ms.ToArray();
    }

    private static byte[] UnwrapDek(byte[] recipients, string passphrase)
    {
        byte[]? dek;
        if (!string.IsNullOrEmpty(passphrase) && TryUnwrapWithPass(recipients, passphrase, out dek)) return dek!;
        if (OperatingSystem.IsWindows())
        {
            if (TryUnwrapWithDpapi(recipients, DataProtectionScope.CurrentUser, out dek)) return dek!;
            if (TryUnwrapWithDpapi(recipients, DataProtectionScope.LocalMachine, out dek)) return dek!;
        }
        throw new CryptographicException("No se pudo desenvelopar la DEK (clave/DPAPI inválidos o entradas ausentes)");
    }

    private static bool TryUnwrapWithPass(byte[] recipients, string passphrase, out byte[]? dek)
    {
        dek = null; int i = 0;
        while (i + 5 <= recipients.Length)
        {
            byte type = recipients[i++];
            int len = BitConverter.ToInt32(recipients, i); i += 4;
            if (len < 0 || i + len > recipients.Length) break;
            if (type == REC_Passphrase)
            {
                int off = i;
                byte kdfId = recipients[off++];
                int iterations = BitConverter.ToInt32(recipients, off); off += 4; // PBKDF2 only
                byte[] salt = recipients.AsSpan(off, SaltSize).ToArray(); off += SaltSize;
                byte[] nonce = recipients.AsSpan(off, GcmNonceSize).ToArray(); off += GcmNonceSize;
                byte[] wrapped = recipients.AsSpan(off, 32).ToArray(); off += 32;
                byte[] tag = recipients.AsSpan(off, GcmTagSize).ToArray(); off += GcmTagSize;
                string kdfName = (kdfId == KDF_ARGON2ID) ? "argon2id" : "pbkdf2";
                byte[] kek = DeriveKey(passphrase, salt, 32, kdfName);
                byte[] outDek = new byte[32];
                using (var gcm = new AesGcm(kek))
                {
                    try { gcm.Decrypt(nonce, wrapped, tag, outDek); }
                    catch { outDek = Array.Empty<byte>(); }
                }
                Array.Clear(kek, 0, kek.Length);
                if (outDek.Length == 32) { dek = outDek; return true; }
            }
            i += len;
        }
        return false;
    }

    private static bool TryUnwrapWithDpapi(byte[] recipients, DataProtectionScope scope, out byte[]? dek)
    {
        dek = null; if (!OperatingSystem.IsWindows()) return false; int i = 0;
        while (i + 5 <= recipients.Length)
        {
            byte type = recipients[i++];
            int len = BitConverter.ToInt32(recipients, i); i += 4;
            if (len < 0 || i + len > recipients.Length) break;
            bool want = (scope == DataProtectionScope.CurrentUser && type == REC_DpapiUser) || (scope == DataProtectionScope.LocalMachine && type == REC_DpapiMachine);
            if (want)
            {
                int off = i;
                byte recScope = recipients[off++];
                int blobLen = BitConverter.ToInt32(recipients, off); off += 4;
                byte[] blob = recipients.AsSpan(off, blobLen).ToArray(); off += blobLen;
                try { byte[] outDek = ProtectedData.Unprotect(blob, null, scope); if (outDek.Length == 32) { dek = outDek; return true; } }
                catch { }
            }
            i += len;
        }
        return false;
    }

    // ---------- Utilities ----------
    private static Options ParseArgs(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            bool has(int off = 1) => i + off < args.Length;
            switch (a.ToLowerInvariant())
            {
                case "--path": if (has()) o.Folder = args[++i]; break;
                case "--chunkmb": if (has() && int.TryParse(args[++i], out int mb)) o.ChunkSize = Math.Max(64 * 1024, mb * 1024 * 1024); break;
                case "--workers": if (has() && int.TryParse(args[++i], out int w)) o.Workers = Math.Max(1, w); break;
                case "--files": if (has() && int.TryParse(args[++i], out int fp)) o.FileParallelism = Math.Max(1, fp); break;
                case "--delete": o.DeletePlaintext = true; break;
                case "--yes": o.Yes = true; break;
                case "--kdf": if (has()) o.Kdf = args[++i]; break;
                case "--include-ext": if (has()) o.IncludeExt = SplitExts(args[++i]); break;
                case "--exclude-ext": if (has()) o.ExcludeExt = SplitExts(args[++i]); break;
                case "--aad": if (has()) o.UserAad = args[++i]; break;
                case "--add-dpapi-user": o.AddDpapiUser = true; break;
                case "--add-dpapi-machine": o.AddDpapiMachine = true; break;
                case "--fileless-enc": if (has()) o.FilelessEncPath = args[++i]; break;
                case "--fileless-dec": o.FilelessDec = true; break;
                case "--out": if (has()) o.FilelessDecOut = args[++i]; break;
            }
        }
        return o;
    }

    private static HashSet<string> SplitExts(string csv)
    {
        var set = new HashSet<string>();
        foreach (var raw in csv.Split(',', ';', ' ', StringSplitOptions.RemoveEmptyEntries))
        {
            string e = raw.Trim().ToLowerInvariant(); if (!e.StartsWith('.')) e = "." + e; set.Add(e);
        }
        return set;
    }

    private static bool FilterByExt(string path, Options o)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        if (o.ExcludeExt.Count > 0 && o.ExcludeExt.Contains(ext)) return false;
        if (o.IncludeExt.Count == 0) return true;
        return o.IncludeExt.Contains(ext);
    }

    private static bool IsProcessableFile(string path)
    {
        try { var attr = File.GetAttributes(path); bool isHidden = (attr & FileAttributes.Hidden) != 0; bool isSystem = (attr & FileAttributes.System) != 0; return !isHidden && !isSystem; }
        catch { return false; }
    }

    private static void ReplaceFile(string temp, string dest)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        if (File.Exists(dest)) File.Delete(dest);
        File.Move(temp, dest);
    }

    private static void TrySecureDelete(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            var info = new FileInfo(path);
            long len = info.Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                byte[] zero = new byte[1024 * 1024];
                long left = len;
                while (left > 0)
                { int toWrite = (int)Math.Min(zero.Length, left); fs.Write(zero, 0, toWrite); left -= toWrite; }
                fs.Flush(true);
            }
            File.Delete(path);
        }
        catch { }
    }

    private static byte[] DeriveKey(string pass, byte[] salt, int bytes, string kdfName)
    {
        if (kdfName.Equals("argon2id", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var t = Type.GetType("Konscious.Security.Cryptography.Argon2id, Konscious.Security.Cryptography");
                if (t != null)
                {
                    using var argon = (IDisposable)Activator.CreateInstance(t, Encoding.UTF8.GetBytes(pass))!;
                    t.GetProperty("Salt")!.SetValue(argon, salt);
                    t.GetProperty("DegreeOfParallelism")!.SetValue(argon, Math.Max(1, Environment.ProcessorCount / 2));
                    t.GetProperty("Iterations")!.SetValue(argon, 3);
                    t.GetProperty("MemorySize")!.SetValue(argon, 256 * 1024); // 256 MB
                    var getBytes = t.GetMethod("GetBytes", new[] { typeof(int) })!;
                    return (byte[])getBytes.Invoke(argon, new object[] { bytes })!;
                }
            }
            catch { }
        }
        using var kdf = new Rfc2898DeriveBytes(pass, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256);
        return kdf.GetBytes(bytes);
    }

    private static byte[] RandomBytes(int len) { byte[] b = new byte[len]; RandomNumberGenerator.Fill(b); return b; }
    private static byte[] SHA256(byte[] data) { using var sha = System.Security.Cryptography.SHA256.Create(); return sha.ComputeHash(data); }

    private static int ReadExact(Stream s, byte[] buf, int count)
    {
        int off = 0; while (off < count) { int r = s.Read(buf, off, count - off); if (r <= 0) break; off += r; }
        return off;
    }

    private static byte[] DeriveNonce(byte[] baseNonce, long idx)
    {
        byte[] n = new byte[GcmNonceSize]; Buffer.BlockCopy(baseNonce, 0, n, 0, GcmNonceSize); uint c = (uint)idx;
        n[8] ^= (byte)(c & 0xFF); n[9] ^= (byte)((c >> 8) & 0xFF); n[10] ^= (byte)((c >> 16) & 0xFF); n[11] ^= (byte)((c >> 24) & 0xFF); return n;
    }

    private static long ComputeTotalChunks(long len, int chunkSize) { if (len == 0) return 1; return (len + chunkSize - 1) / chunkSize; }

    private static void WriteInt64LE(byte[] buf, int offset, long value)
    {
        unchecked { buf[offset + 0] = (byte)(value & 0xFF); buf[offset + 1] = (byte)((value >> 8) & 0xFF); buf[offset + 2] = (byte)((value >> 16) & 0xFF); buf[offset + 3] = (byte)((value >> 24) & 0xFF); buf[offset + 4] = (byte)((value >> 32) & 0xFF); buf[offset + 5] = (byte)((value >> 40) & 0xFF); buf[offset + 6] = (byte)((value >> 48) & 0xFF); buf[offset + 7] = (byte)((value >> 56) & 0xFF); }
    }

    private static string ReadPasswordAllowEmpty()
    {
        var sb = new StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) { sb.Length--; Console.Write(" "); } }
            else if (!char.IsControl(k.KeyChar)) { sb.Append(k.KeyChar); Console.Write("*"); }
        }
        return sb.ToString();
    }

    private static string PromptRepeat(string original)
    {
        Console.Write("
Repite la contraseña: "); var again = ReadPasswordAllowEmpty(); Console.WriteLine(); if (again != original) { Console.WriteLine("No coincide."); Environment.Exit(1); } return again;
    }
}
