using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

// EBOX v4 — AEAD-only (AES-GCM) with chunked streaming + envelope (per-file DEK)
// Enhancements applied:
// - FILELESS modes:
//     * --fileless-enc <path>   -> write EBOX stream to STDOUT (no .enc on disk)
//     * --fileless-dec [--out <path>] -> read EBOX from STDIN, write plaintext to STDOUT or file
// - PERFORMANCE & QUIET OPERATION:
//     * Pipeline with Channels: read -> encrypt (N workers) -> write (in-order)
//     * Parallel per-file and per-chunk encryption
//     * ArrayPool<byte> buffers, minimal allocations
//     * Pre-allocate destination size with SetLength
//     * Optional throttling: --max-mbps, --max-iops
//     * **Adaptive backoff**: --auto-backoff ajusta el throughput según carga de CPU (GetSystemTimes)
//     * Background/low-impact mode: --background lowers CPU & I/O priority (Windows)
//     * Quiet logging: --quiet (solo errores); --debug (trazas por chunk a STDERR)
// - SIZE PRIVACY:
//     * Optional padding multiple (--padMB X): pads plaintext to next multiple (random bytes), stores OrigLen & PaddedLen in TLV
// - IN-PLACE OPS:
//     * --inplace : sobreescribe el archivo original de forma atómica (mismo nombre)
//     * --rename-ext .enc : junto a --inplace, renombra en el replace (p. ej., file -> file.enc) y elimina el original
// - VERIFY:
//     * --verify : re-verifica tags tras cifrar (sin escribir claro)
// - Other:
//     * DPAPI recipients (user/machine) opcional; Passphrase recipient via PBKDF2 o Argon2id
//     * TLV metadata (orig len, padded len, mtime/ctime, user AAD) autenticados

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
    private const byte TLV_PaddedLen = 0x05;     // 8 bytes (Int64)

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
        public long PadMultiple = 0; // bytes; 0 = no padding. Set via --padMB
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
        public bool Debug = false;
        public bool Verify = false;
        public bool InPlaceEnc = false;
        public string? RenameExt = null; // e.g. ".enc" (only with --inplace)
        public bool Quiet = false;
        public bool Background = false;
        public double MaxMbps = 0; // ceiling for throughput (MB/s); 0 = no fixed cap
        public int MaxIops = 0;    // max chunks per second if >0

        // Adaptive backoff
        public bool AutoBackoff = false;
        public int CpuHighPct = 75;      // reduce rate when above
        public int CpuLowPct = 40;      // increase rate when below
        public int BackoffIntervalMs = 1200;
        public double BackoffDown = 0.85; // multiply rate when high
        public double BackoffUp = 1.15; // multiply rate when low
        public double MinMbps = 0;       // floor (0 = allow near-stop)

        // fileless modes
        public string? FilelessEncPath = null; // encrypt this file to stdout
        public bool FilelessDec = false;       // decrypt from stdin
        public string? FilelessDecOut = null;  // optional output path for fileless dec
    }

    static void Main(string[] args)
    {
        var opt = ParseArgs(args);

        if (opt.Background) EnterBackgroundMode();

        // FILELESS ENCRYPT: read from file, write to STDOUT
        if (!string.IsNullOrEmpty(opt.FilelessEncPath))
        {
            if (!File.Exists(opt.FilelessEncPath)) { LogErr("Input no existe"); return; }
            Console.Error.Write("Contraseña (Enter para vacía y solo DPAPI): ");
            string pass = ReadPasswordAllowEmpty(); Console.Error.WriteLine();

            EncryptSingleFileToStream(opt.FilelessEncPath!, Console.OpenStandardOutput(), opt, pass, fileless: true, targetPathForPrealloc: null);
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
                DecryptStreamToStream(stdin, stdout, decPass, opt);
            }
            else
            {
                DecryptStreamToFile(stdin, opt.FilelessDecOut, decPass, opt);
            }
            return;
        }

        // DIRECTORY MODE
        if (!Directory.Exists(opt.Folder)) { Log($"No existe la carpeta: {opt.Folder}", opt); return; }

        Console.Write("Contraseña (Enter para vacía y solo DPAPI): ");
        string pass1 = ReadPasswordAllowEmpty();
        string pass2 = pass1.Length > 0 ? PromptRepeat(pass1) : string.Empty;

        var files = Directory.EnumerateFiles(opt.Folder, "*", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
            .Where(IsProcessableFile)
            .Where(f => FilterByExt(f, opt))
            .ToList();
        if (files.Count == 0) { Log("No hay archivos para cifrar.", opt); return; }

        if ((opt.DeletePlaintext || opt.InPlaceEnc) && !opt.Yes)
        {
            Console.Write("Esto sobreescribirá/borrará originales. Confirmar (escribe 'SI'): ");
            var conf = Console.ReadLine();
            if (!string.Equals(conf, "SI", StringComparison.OrdinalIgnoreCase))
            { Log("Abortado.", opt); return; }
        }

        Log($"Archivos: {files.Count} | Chunk: {opt.ChunkSize / (1024 * 1024)} MiB | Workers/archivo: {opt.Workers} | Archivos en paralelo: {opt.FileParallelism} | Pad: {(opt.PadMultiple > 0 ? ($"{opt.PadMultiple / (1024 * 1024)} MiB") : "no")}
", opt);

        var queue = new ConcurrentQueue<string>(files);
        int ok = 0, err = 0, del = 0;
        Parallel.For(0, Math.Max(1, opt.FileParallelism), _ =>
        {
            while (queue.TryDequeue(out var input))
            {
                try
                {
                    string targetPath = opt.InPlaceEnc ? (opt.RenameExt != null ? ChangeExtensionSafe(input, opt.RenameExt) : input)
                                                       : input + ".enc";
                    string tmp = targetPath + ".tmp";

                    using var ofs = new FileStream(tmp, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 1 << 20, FileOptions.SequentialScan);
                    TryLowerIoPriority(ofs.SafeFileHandle);
                    EncryptSingleFileToStream(input, ofs, opt, pass1, fileless: false, targetPathForPrealloc: targetPath);
                    ofs.Flush(true); ofs.Close();

                    ReplaceFile(tmp, targetPath);

                    if (opt.InPlaceEnc && opt.RenameExt != null && !PathsEqual(targetPath, input))
                    { TrySecureDelete(input); Interlocked.Increment(ref del); }
                    else if (opt.DeletePlaintext) { TrySecureDelete(input); Interlocked.Increment(ref del); }

                    if (opt.Verify) VerifyEboxFile(targetPath, pass1, opt);

                    Log($"[OK] {Path.GetFileName(input)} -> {Path.GetFileName(targetPath)}", opt);
                    Interlocked.Increment(ref ok);
                }
                catch (Exception ex)
                {
                    LogErr($"[ERR] {Path.GetFileName(input)}: {ex.Message}");
                    Interlocked.Increment(ref err);
                }
            }
        });

        Log($"
Completado.Éxitos: { ok} | Errores: { err} | Eliminados: { del}
        ", opt);
    }

    private static bool PathsEqual(string a, string b) => string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);
    private static string ChangeExtensionSafe(string path, string newExt)
    { if (!newExt.StartsWith('.')) newExt = "." + newExt; return Path.Combine(Path.GetDirectoryName(path)!, Path.GetFileNameWithoutExtension(path) + newExt); }

    // ---------- Core: Encrypt single file to target stream with pipeline ----------
    private static void EncryptSingleFileToStream(string inputPath, Stream targetStream, Options opt, string passphrase, bool fileless, string? targetPathForPrealloc)
    {
        using var outFs = targetStream; // owns stream
        var info = new FileInfo(inputPath);
        TryLowerIoPriority(GetSafeHandle(outFs));

        long origLen = info.Length;
        long padBlock = opt.PadMultiple > 0 ? opt.PadMultiple : 0;
        long paddedLen = padBlock > 0 ? RoundUp(origLen, padBlock) : origLen;
        long totalChunks = ComputeTotalChunks(paddedLen, opt.ChunkSize);

        // 1) Per-file DEK
        byte[] dek = RandomBytes(32);

        // 2) TLV meta (with padded len)
        byte[] tlvMeta = BuildTlvMeta(info, opt.UserAad, paddedLen);

        // 3) Recipients (pass + DPAPI)
        byte[] recipients = BuildRecipients(dek, passphrase, opt.Kdf, opt.AddDpapiUser, opt.AddDpapiMachine);

        // 4) Stream params
        byte[] baseNonce = RandomBytes(GcmNonceSize);

        // 5) Header and headerHash (AAD)
        byte[] header = BuildHeader(tlvMeta, recipients, opt.ChunkSize, baseNonce, totalChunks);
        byte[] headerHash = SHA256(header);

        // 6) Pre-allocate
        if (!fileless && outFs is FileStream ofs && targetPathForPrealloc != null)
        {
            long headerLen = header.Length;
            long totalTags = totalChunks * GcmTagSize;
            long totalSize = headerLen + paddedLen + totalTags;
            ofs.SetLength(totalSize);
        }

        // 7) Write header
        outFs.Write(header, 0, header.Length);

        // 8) Pipeline
        var readChan = Channel.CreateBounded<PlainChunk>(new BoundedChannelOptions(Math.Max(2, opt.Workers * 2)) { FullMode = BoundedChannelFullMode.Wait });
        var encChan = Channel.CreateBounded<EncChunk>(new BoundedChannelOptions(Math.Max(2, opt.Workers * 2)) { FullMode = BoundedChannelFullMode.Wait });

        var readerTask = Task.Run(() => ReaderLoop(inputPath, readChan.Writer, opt.ChunkSize, opt));

        var workerTasks = new List<Task>();
        for (int w = 0; w < opt.Workers; w++)
        { workerTasks.Add(Task.Run(() => EncryptLoop(readChan.Reader, encChan.Writer, dek, headerHash, baseNonce, opt.ChunkSize, paddedLen, opt))); }

        var writerTask = Task.Run(() => WriterLoop(encChan.Reader, outFs, opt));

        Task.WaitAll(workerTasks.ToArray());
        encChan.Writer.Complete();
        writerTask.Wait();

        Array.Clear(dek, 0, dek.Length);
        outFs.Flush();
    }

    // ---------- Reader ----------
    private struct PlainChunk { public long Index; public int Length; public byte[] Buffer; public bool IsLast; }
    private static void ReaderLoop(string inputPath, ChannelWriter<PlainChunk> writer, int chunkSize, Options opt)
    {
        var pool = ArrayPool<byte>.Shared;
        try
        {
            using var inFs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
            TryLowerIoPriority(inFs.SafeFileHandle);
            long idx = 0;
            while (true)
            {
                byte[] buf = pool.Rent(chunkSize);
                int r = ReadExact(inFs, buf, chunkSize);
                if (r == 0) { pool.Return(buf); break; }
                bool isLast = inFs.Position == inFs.Length;
                writer.WriteAsync(new PlainChunk { Index = idx++, Length = r, Buffer = buf, IsLast = isLast }).AsTask().Wait();
                if (r < chunkSize) break;
            }
        }
        finally { writer.Complete(); }
    }

    // ---------- Encrypt workers ----------
    private struct EncChunk { public long Index; public int Length; public byte[] Cipher; public byte[] Tag; public byte[] PlainBuf; }
    private static void EncryptLoop(ChannelReader<PlainChunk> reader, ChannelWriter<EncChunk> writer, byte[] dek, byte[] headerHash, byte[] baseNonce, int chunkSize, long paddedLen, Options opt)
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
                    long offset = pc.Index * (long)chunkSize;
                    int targetLen = (int)Math.Min(chunkSize, Math.Max(0, paddedLen - offset));
                    if (targetLen < 0) targetLen = 0;

                    byte[] plainForEnc;
                    if (pc.Length == targetLen)
                    { plainForEnc = pc.Buffer; }
                    else
                    {
                        plainForEnc = pool.Rent(targetLen);
                        Buffer.BlockCopy(pc.Buffer, 0, plainForEnc, 0, pc.Length);
                        if (targetLen > pc.Length)
                        { var pad = plainForEnc.AsSpan(pc.Length, targetLen - pc.Length); RandomNumberGenerator.Fill(pad); }
                    }

                    byte[] cipher = pool.Rent(targetLen);
                    byte[] tag = pool.Rent(GcmTagSize);
                    byte[] nonce = DeriveNonce(baseNonce, pc.Index);
                    WriteInt64LE(aad, headerHash.Length, pc.Index);

                    gcm.Encrypt(nonce, plainForEnc.AsSpan(0, targetLen), cipher.AsSpan(0, targetLen), tag.AsSpan(0, GcmTagSize), aad);

                    if (!ReferenceEquals(plainForEnc, pc.Buffer)) pool.Return(plainForEnc);
                    if (opt.Debug) Console.Error.WriteLine($"[enc] idx={pc.Index} len={targetLen}");

                    writer.WriteAsync(new EncChunk { Index = pc.Index, Length = targetLen, Cipher = cipher, Tag = tag, PlainBuf = pc.Buffer }).AsTask().Wait();
                }
            }
        }
        finally { writer.TryComplete(); }
    }

    // ---------- Token bucket (dynamic) ----------
    private sealed class TokenBucket
    {
        private double _rateBytesPerSec; // current rate
        private double _tokens;
        private long _lastTicks;
        private readonly object _lock = new object();
        public TokenBucket(double initialRate)
        {
            _rateBytesPerSec = Math.Max(1, initialRate); _tokens = _rateBytesPerSec; _lastTicks = Stopwatch.GetTimestamp();
        }
        public void UpdateRate(double newRate)
        {
            lock (_lock)
            {
                _rateBytesPerSec = Math.Max(1, newRate);
                _tokens = Math.Min(_tokens, _rateBytesPerSec);
            }
        }
        public double CurrentRate => _rateBytesPerSec;
        public void Consume(int bytes)
        {
            lock (_lock)
            {
                long now = Stopwatch.GetTimestamp();
                double dt = (now - _lastTicks) / (double)Stopwatch.Frequency;
                _lastTicks = now;
                _tokens = Math.Min(_rateBytesPerSec, _tokens + dt * _rateBytesPerSec);
                if (_tokens >= bytes)
                {
                    _tokens -= bytes; return;
                }
                double deficit = bytes - _tokens; double sleepSec = deficit / _rateBytesPerSec;
                _tokens = 0;
                if (sleepSec > 0) Monitor.Wait(_lock, TimeSpan.FromSeconds(sleepSec));
            }
        }
    }

    // ---------- Adaptive backoff monitor ----------
    private static Task StartBackoffMonitor(TokenBucket bucket, Options opt, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Task.CompletedTask; // simple Windows-only impl
        var meter = new CpuMeter();
        double maxBps = opt.MaxMbps > 0 ? opt.MaxMbps * 1024 * 1024 : double.PositiveInfinity;
        double minBps = opt.MinMbps > 0 ? opt.MinMbps * 1024 * 1024 : 1;
        return Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(opt.BackoffIntervalMs, ct).ContinueWith(_ => { });
                try
                {
                    var usage = meter.SampleUsage(); // 0..1
                    double curr = bucket.CurrentRate;
                    double next = curr;
                    if (usage * 100 >= opt.CpuHighPct)
                        next = Math.Max(minBps, curr * opt.BackoffDown);
                    else if (usage * 100 <= opt.CpuLowPct)
                        next = curr * opt.BackoffUp;

                    if (double.IsFinite(maxBps)) next = Math.Min(next, maxBps);

                    if (Math.Abs(next - curr) / curr > 0.05)
                    {
                        bucket.UpdateRate(next);
                        if (opt.Debug) Console.Error.WriteLine($"[backoff] cpu={(usage * 100):F0}% rate={(next / 1024 / 1024):F2} MB/s");
                    }
                }
                catch { }
            }
        }, ct);
    }

    // Windows CPU usage sampler via GetSystemTimes
    [StructLayout(LayoutKind.Sequential)] private struct FILETIME { public uint LowDateTime; public uint HighDateTime; }
    [DllImport("kernel32.dll", SetLastError = false)] private static extern bool GetSystemTimes(out FILETIME idleTime, out FILETIME kernelTime, out FILETIME userTime);
    private sealed class CpuMeter
    {
        private ulong _prevIdle, _prevKernel, _prevUser; private bool _init = false;
        private static ulong ToUInt64(FILETIME ft) => ((ulong)ft.HighDateTime << 32) | ft.LowDateTime;
        public double SampleUsage()
        {
            if (!GetSystemTimes(out var idle, out var kernel, out var user)) return 0.0;
            ulong i = ToUInt64(idle), k = ToUInt64(kernel), u = ToUInt64(user);
            if (!_init) { _prevIdle = i; _prevKernel = k; _prevUser = u; _init = true; return 0.0; }
            ulong di = i - _prevIdle; ulong dk = k - _prevKernel; ulong du = u - _prevUser;
            _prevIdle = i; _prevKernel = k; _prevUser = u;
            ulong total = dk + du; if (total == 0) return 0.0;
            ulong busy = total > di ? (total - di) : 0; // kernel includes idle
            return Math.Min(1.0, busy / (double)total);
        }
    }

    // ---------- Writer with throttling + adaptive backoff ----------
    private static void WriterLoop(ChannelReader<EncChunk> reader, Stream outFs, Options opt)
    {
        var pool = ArrayPool<byte>.Shared;
        long expect = 0;
        var pending = new SortedDictionary<long, EncChunk>();
        double initialBps = (opt.MaxMbps > 0 ? opt.MaxMbps : 1_000_000_000) * 1024 * 1024; // ~infinite if not set
        TokenBucket? bucket = new TokenBucket(initialBps);
        CancellationTokenSource? cts = null; Task? backoffTask = null;
        if (opt.AutoBackoff) { cts = new CancellationTokenSource(); backoffTask = StartBackoffMonitor(bucket, opt, cts.Token); }

        int iopsBudget = opt.MaxIops;
        long iopsWindowStart = Stopwatch.GetTimestamp();
        int iopsCount = 0;

        void Throttle(int bytes)
        {
            bucket?.Consume(bytes);
            if (iopsBudget > 0)
            {
                long now = Stopwatch.GetTimestamp();
                double sec = (now - iopsWindowStart) / (double)Stopwatch.Frequency;
                if (sec >= 1) { iopsWindowStart = now; iopsCount = 0; }
                iopsCount++;
                if (iopsCount > iopsBudget) { Thread.Sleep(1000 - (int)(sec * 1000)); iopsWindowStart = Stopwatch.GetTimestamp(); iopsCount = 0; }
            }
        }

        void FlushChunk(ref EncChunk ec)
        {
            Throttle(ec.Length + GcmTagSize);
            outFs.Write(ec.Cipher, 0, ec.Length);
            outFs.Write(ec.Tag, 0, GcmTagSize);
            pool.Return(ec.Cipher); pool.Return(ec.Tag); pool.Return(ec.PlainBuf);
        }

        foreach (var ec in reader.ReadAllAsync().ToEnumerable())
        {
            if (ec.Index == expect)
            {
                var curr = ec; FlushChunk(ref curr); expect++;
                while (pending.TryGetValue(expect, out var nxt)) { pending.Remove(expect); FlushChunk(ref nxt); expect++; }
            }
            else { pending[ec.Index] = ec; }
        }
        while (pending.TryGetValue(expect, out var nxt2)) { pending.Remove(expect); FlushChunk(ref nxt2); expect++; }

        cts?.Cancel(); backoffTask?.Wait(2000);
    }

    // ---------- Decrypt from stream to stream ----------
    private class RestoredMeta { public long? MTimeUtcTicks; public long? CTimeUtcTicks; public long? OrigLen; public long? PaddedLen; }

    private static void DecryptStreamToStream(Stream inStream, Stream outStream, string passphrase, Options opt)
    {
        using var br = new BinaryReader(inStream, Encoding.UTF8, leaveOpen: true);
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
        int reserved = br.ReadInt32();

        byte[] header = BuildHeader(tlv, recipients, chunkSize, baseNonce, totalChunks);
        byte[] headerHash = SHA256(header);

        byte[] dek = UnwrapDek(recipients, passphrase);

        using var gcm = new AesGcm(dek);
        var pool = ArrayPool<byte>.Shared;
        byte[] aad = new byte[headerHash.Length + sizeof(long)];
        Buffer.BlockCopy(headerHash, 0, aad, 0, headerHash.Length);

        long paddedLen = meta.PaddedLen ?? meta.OrigLen ?? throw new InvalidDataException("TLV sin longitudes válidas");
        long remainingOrig = meta.OrigLen ?? throw new InvalidDataException("TLV sin longitud original");

        // Throttle+backoff also for decrypt writes
        double initialBps = (opt.MaxMbps > 0 ? opt.MaxMbps : 1_000_000_000) * 1024 * 1024;
        var bucket = new TokenBucket(initialBps);
        CancellationTokenSource? cts = null; Task? backoffTask = null;
        if (opt.AutoBackoff) { cts = new CancellationTokenSource(); backoffTask = StartBackoffMonitor(bucket, opt, cts.Token); }
        int iopsBudget = opt.MaxIops; long iopsWindowStart = Stopwatch.GetTimestamp(); int iopsCount = 0;
        void Throttle(int bytes)
        {
            bucket?.Consume(bytes);
            if (iopsBudget > 0)
            {
                long now = Stopwatch.GetTimestamp(); double sec = (now - iopsWindowStart) / (double)Stopwatch.Frequency;
                if (sec >= 1) { iopsWindowStart = now; iopsCount = 0; }
                iopsCount++; if (iopsCount > iopsBudget) { Thread.Sleep(1000 - (int)(sec * 1000)); iopsWindowStart = Stopwatch.GetTimestamp(); iopsCount = 0; }
            }
        }

        for (long idx = 0; idx < totalChunks; idx++)
        {
            long offset = idx * (long)chunkSize;
            int thisLen = (int)Math.Min(chunkSize, Math.Max(0, paddedLen - offset));
            byte[] cipher = pool.Rent(thisLen);
            int readCipher = ReadExact(inStream, cipher, thisLen); if (readCipher != thisLen) throw new EndOfStreamException();
            byte[] tag = pool.Rent(GcmTagSize);
            int readTag = ReadExact(inStream, tag, GcmTagSize); if (readTag != GcmTagSize) throw new EndOfStreamException();

            byte[] nonce = DeriveNonce(baseNonce, idx);
            WriteInt64LE(aad, headerHash.Length, idx);

            byte[] plain = pool.Rent(thisLen);
            gcm.Decrypt(nonce, cipher.AsSpan(0, thisLen), tag.AsSpan(0, GcmTagSize), plain.AsSpan(0, thisLen), aad);

            int writeLen = (int)Math.Min(remainingOrig, (long)thisLen);
            if (writeLen > 0)
            {
                Throttle(writeLen);
                outStream.Write(plain, 0, writeLen);
            }
            if (opt.Debug) Console.Error.WriteLine($"[dec] idx={idx} len={thisLen} write={writeLen}");

            pool.Return(cipher); pool.Return(tag); pool.Return(plain);
            remainingOrig -= writeLen;
        }
        Array.Clear(dek, 0, dek.Length);
        outStream.Flush();
        cts?.Cancel(); backoffTask?.Wait(2000);
    }

    private static void DecryptStreamToFile(Stream inStream, string outputPath, string passphrase, Options opt)
    {
        using var temp = new FileStream(outputPath + ".tmp", FileMode.Create, FileAccess.ReadWrite, FileShare.None, 1 << 20, FileOptions.SequentialScan);
        TryLowerIoPriority(temp.SafeFileHandle);
        DecryptStreamToStream(inStream, temp, passphrase, opt);
        temp.Flush(true); temp.Close(); ReplaceFile(outputPath + ".tmp", outputPath);
    }

    private static void VerifyEboxFile(string path, string passphrase, Options opt)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        TryLowerIoPriority(fs.SafeFileHandle);
        DecryptStreamToStream(fs, Stream.Null, passphrase, opt);
        Log($"[VERIFY] OK: {Path.GetFileName(path)}", opt);
    }

    // ---------- Header & helpers ----------
    private static byte[] BuildHeader(byte[] tlv, byte[] recipients, int chunkSize, byte[] baseNonce, long totalChunks)
    {
        using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms);
        bw.Write(Magic); bw.Write((byte)FileVersion); bw.Write((byte)AlgoChunkedGcm);
        bw.Write(tlv.Length); bw.Write(tlv);
        bw.Write(recipients.Length); bw.Write(recipients);
        bw.Write(chunkSize); bw.Write(baseNonce); bw.Write(totalChunks); bw.Write(0);
        bw.Flush(); return ms.ToArray();
    }

    private class ParsedMeta
    { public long? OrigLen; public long? MTimeUtcTicks; public long? CTimeUtcTicks; public string? UserAad; public long? PaddedLen; }

    private static ParsedMeta ParseTlv(byte[] tlv)
    {
        var meta = new ParsedMeta(); int i = 0;
        while (i + 3 <= tlv.Length)
        {
            byte t = tlv[i++]; int len = BitConverter.ToUInt16(tlv, i); i += 2; if (len < 0 || i + len > tlv.Length) break;
            switch (t)
            {
                case TLV_OrigLen: if (len == 8) meta.OrigLen = BitConverter.ToInt64(tlv, i); break;
                case TLV_MTimeUtcTicks: if (len == 8) meta.MTimeUtcTicks = BitConverter.ToInt64(tlv, i); break;
                case TLV_CTimeUtcTicks: if (len == 8) meta.CTimeUtcTicks = BitConverter.ToInt64(tlv, i); break;
                case TLV_UserAad: meta.UserAad = Encoding.UTF8.GetString(tlv, i, len); break;
                case TLV_PaddedLen: if (len == 8) meta.PaddedLen = BitConverter.ToInt64(tlv, i); break;
                default: break;
            }
            i += len;
        }
        return meta;
    }

    private static byte[] BuildTlvMeta(FileInfo fi, string userAad, long paddedLen)
    {
        using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms);
        void TLV(byte t, byte[] payload) { bw.Write(t); bw.Write((ushort)payload.Length); bw.Write(payload); }
        TLV(TLV_OrigLen, BitConverter.GetBytes(fi.Length));
        TLV(TLV_PaddedLen, BitConverter.GetBytes(paddedLen));
        TLV(TLV_MTimeUtcTicks, BitConverter.GetBytes(fi.LastWriteTimeUtc.Ticks));
        TLV(TLV_CTimeUtcTicks, BitConverter.GetBytes(fi.CreationTimeUtc.Ticks));
        if (!string.IsNullOrEmpty(userAad)) TLV(TLV_UserAad, Encoding.UTF8.GetBytes(userAad));
        bw.Flush(); return ms.ToArray();
    }

    private static byte[] BuildRecipients(byte[] dek, string passphrase, string kdfName, bool addDpapiUser, bool addDpapiMachine)
    {
        using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms);
        if (!string.IsNullOrEmpty(passphrase))
        {
            byte kdfId = kdfName.Equals("argon2id", StringComparison.OrdinalIgnoreCase) ? KDF_ARGON2ID : KDF_PBKDF2;
            byte[] salt = RandomBytes(SaltSize);
            byte[] kek = DeriveKey(passphrase, salt, 32, kdfName);
            byte[] nonce = RandomBytes(GcmNonceSize);
            byte[] wrapped = new byte[dek.Length]; byte[] tag = new byte[GcmTagSize];
            using (var gcm = new AesGcm(kek)) gcm.Encrypt(nonce, dek, wrapped, tag);
            using var rec = new MemoryStream(); using (var wr = new BinaryWriter(rec))
            { wr.Write((byte)kdfId); wr.Write(Pbkdf2Iterations); wr.Write(salt); wr.Write(nonce); wr.Write(wrapped); wr.Write(tag); }
            WriteRecipient(bw, REC_Passphrase, rec.ToArray()); Array.Clear(kek, 0, kek.Length);
        }
        if (addDpapiUser || addDpapiMachine)
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI solo disponible en Windows");
            if (addDpapiUser) { var blob = ProtectedData.Protect(dek, null, DataProtectionScope.CurrentUser); WriteRecipient(bw, REC_DpapiUser, BuildDpapiPayload(blob, 1)); }
            if (addDpapiMachine) { var blob = ProtectedData.Protect(dek, null, DataProtectionScope.LocalMachine); WriteRecipient(bw, REC_DpapiMachine, BuildDpapiPayload(blob, 2)); }
        }
        bw.Flush(); return ms.ToArray();
    }

    private static void WriteRecipient(BinaryWriter bw, byte type, byte[] payload) { bw.Write(type); bw.Write(payload.Length); bw.Write(payload); }

    private static byte[] BuildDpapiPayload(byte[] blob, byte scope)
    { using var ms = new MemoryStream(); using var bw = new BinaryWriter(ms); bw.Write(scope); bw.Write(blob.Length); bw.Write(blob); bw.Flush(); return ms.ToArray(); }

    private static byte[] UnwrapDek(byte[] recipients, string passphrase)
    {
        byte[]? dek; if (!string.IsNullOrEmpty(passphrase) && TryUnwrapWithPass(recipients, passphrase, out dek)) return dek!;
        if (OperatingSystem.IsWindows()) { if (TryUnwrapWithDpapi(recipients, DataProtectionScope.CurrentUser, out dek)) return dek!; if (TryUnwrapWithDpapi(recipients, DataProtectionScope.LocalMachine, out dek)) return dek!; }
        throw new CryptographicException("No se pudo desenvelopar la DEK (clave/DPAPI inválidos o entradas ausentes)");
    }

    private static bool TryUnwrapWithPass(byte[] recipients, string passphrase, out byte[]? dek)
    {
        dek = null; int i = 0; while (i + 5 <= recipients.Length)
        {
            byte type = recipients[i++]; int len = BitConverter.ToInt32(recipients, i); i += 4; if (len < 0 || i + len > recipients.Length) break;
            if (type == REC_Passphrase)
            {
                int off = i; byte kdfId = recipients[off++]; int iterations = BitConverter.ToInt32(recipients, off); off += 4;
                byte[] salt = recipients.AsSpan(off, SaltSize).ToArray(); off += SaltSize;
                byte[] nonce = recipients.AsSpan(off, GcmNonceSize).ToArray(); off += GcmNonceSize;
                byte[] wrapped = recipients.AsSpan(off, 32).ToArray(); off += 32;
                byte[] tag = recipients.AsSpan(off, GcmTagSize).ToArray(); off += GcmTagSize;
                string kdfName = (kdfId == KDF_ARGON2ID) ? "argon2id" : "pbkdf2";
                byte[] kek = DeriveKey(passphrase, salt, 32, kdfName);
                byte[] outDek = new byte[32]; using (var gcm = new AesGcm(kek)) { try { gcm.Decrypt(nonce, wrapped, tag, outDek); } catch { outDek = Array.Empty<byte>(); } }
                Array.Clear(kek, 0, kek.Length); if (outDek.Length == 32) { dek = outDek; return true; }
            }
            i += len;
        }
        return false;
    }

    private static bool TryUnwrapWithDpapi(byte[] recipients, DataProtectionScope scope, out byte[]? dek)
    {
        dek = null; if (!OperatingSystem.IsWindows()) return false; int i = 0; while (i + 5 <= recipients.Length)
        {
            byte type = recipients[i++]; int len = BitConverter.ToInt32(recipients, i); i += 4; if (len < 0 || i + len > recipients.Length) break;
            bool want = (scope == DataProtectionScope.CurrentUser && type == REC_DpapiUser) || (scope == DataProtectionScope.LocalMachine && type == REC_DpapiMachine);
            if (want)
            {
                int off = i; byte recScope = recipients[off++]; int blobLen = BitConverter.ToInt32(recipients, off); off += 4; byte[] blob = recipients.AsSpan(off, blobLen).ToArray(); off += blobLen;
                try { byte[] outDek = ProtectedData.Unprotect(blob, null, scope); if (outDek.Length == 32) { dek = outDek; return true; } } catch { }
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
            string a = args[i]; bool has(int off = 1) => i + off < args.Length;
            switch (a.ToLowerInvariant())
            {
                case "--path": if (has()) o.Folder = args[++i]; break;
                case "--chunkmb": if (has() && int.TryParse(args[++i], out int mb)) o.ChunkSize = Math.Max(64 * 1024, mb * 1024 * 1024); break;
                case "--padmb": if (has() && int.TryParse(args[++i], out int pmb)) o.PadMultiple = (long)pmb * 1024 * 1024; break;
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
                case "--debug": o.Debug = true; break;
                case "--verify": o.Verify = true; break;
                case "--inplace": o.InPlaceEnc = true; break;
                case "--rename-ext": if (has()) o.RenameExt = args[++i]; break;
                case "--quiet": o.Quiet = true; break;
                case "--background": o.Background = true; break;
                case "--max-mbps": if (has() && double.TryParse(args[++i], out double mbps)) o.MaxMbps = Math.Max(0, mbps); break;
                case "--max-iops": if (has() && int.TryParse(args[++i], out int iops)) o.MaxIops = Math.Max(0, iops); break;
                case "--auto-backoff": o.AutoBackoff = true; break;
                case "--cpu-high": if (has() && int.TryParse(args[++i], out int ch)) o.CpuHighPct = Math.Clamp(ch, 1, 99); break;
                case "--cpu-low": if (has() && int.TryParse(args[++i], out int cl)) o.CpuLowPct = Math.Clamp(cl, 1, 99); break;
                case "--backoff-interval-ms": if (has() && int.TryParse(args[++i], out int bi)) o.BackoffIntervalMs = Math.Max(200, bi); break;
                case "--backoff-down": if (has() && double.TryParse(args[++i], out double bd)) o.BackoffDown = Math.Clamp(bd, 0.1, 0.99); break;
                case "--backoff-up": if (has() && double.TryParse(args[++i], out double bu)) o.BackoffUp = Math.Clamp(bu, 1.01, 3.0); break;
                case "--min-mbps": if (has() && double.TryParse(args[++i], out double minmb)) o.MinMbps = Math.Max(0, minmb); break;
            }
        }
        return o;
    }

    private static long RoundUp(long n, long m) => ((n + m - 1) / m) * m;

    private static HashSet<string> SplitExts(string csv)
    {
        var set = new HashSet<string>();
        foreach (var raw in csv.Split(',', ';', ' ', StringSplitOptions.RemoveEmptyEntries))
        { string e = raw.Trim().ToLowerInvariant(); if (!e.StartsWith('.')) e = "." + e; set.Add(e); }
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
    { try { var attr = File.GetAttributes(path); bool isHidden = (attr & FileAttributes.Hidden) != 0; bool isSystem = (attr & FileAttributes.System) != 0; return !isHidden && !isSystem; } catch { return false; } }

    private static void ReplaceFile(string temp, string dest)
    { Directory.CreateDirectory(Path.GetDirectoryName(dest)!); if (File.Exists(dest)) File.Delete(dest); File.Move(temp, dest); }

    private static void TrySecureDelete(string path)
    {
        try
        {
            if (!File.Exists(path)) return; var info = new FileInfo(path); long len = info.Length;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            { byte[] zero = new byte[1024 * 1024]; long left = len; while (left > 0) { int toWrite = (int)Math.Min(zero.Length, left); fs.Write(zero, 0, toWrite); left -= toWrite; } fs.Flush(true); }
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

    private static int ReadExact(Stream s, byte[] buf, int count) { int off = 0; while (off < count) { int r = s.Read(buf, off, count - off); if (r <= 0) break; off += r; } return off; }

    private static byte[] DeriveNonce(byte[] baseNonce, long idx)
    { byte[] n = new byte[GcmNonceSize]; Buffer.BlockCopy(baseNonce, 0, n, 0, GcmNonceSize); uint c = (uint)idx; n[8] ^= (byte)(c & 0xFF); n[9] ^= (byte)((c >> 8) & 0xFF); n[10] ^= (byte)((c >> 16) & 0xFF); n[11] ^= (byte)((c >> 24) & 0xFF); return n; }

    private static long ComputeTotalChunks(long len, int chunkSize) { if (len == 0) return 1; return (len + chunkSize - 1) / chunkSize; }

    private static void WriteInt64LE(byte[] buf, int offset, long value)
    { unchecked { buf[offset + 0] = (byte)(value & 0xFF); buf[offset + 1] = (byte)((value >> 8) & 0xFF); buf[offset + 2] = (byte)((value >> 16) & 0xFF); buf[offset + 3] = (byte)((value >> 24) & 0xFF); buf[offset + 4] = (byte)((value >> 32) & 0xFF); buf[offset + 5] = (byte)((value >> 40) & 0xFF); buf[offset + 6] = (byte)((value >> 48) & 0xFF); buf[offset + 7] = (byte)((value >> 56) & 0xFF); } }

    // ---------- Logging ----------
    private static void Log(string msg, Options opt) { if (!opt.Quiet) Console.WriteLine(msg); }
    private static void LogErr(string msg) { Console.Error.WriteLine(msg); }

    // ---------- Background & IO priority (Windows) ----------
    private static void EnterBackgroundMode()
    {
        if (!OperatingSystem.IsWindows()) return;
        try { SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN); SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN); }
        catch { }
    }

    private static void TryLowerIoPriority(SafeFileHandle? h)
    {
        if (!OperatingSystem.IsWindows() || h == null || h.IsInvalid) return;
        try { FILE_IO_PRIORITY_HINT_INFO info = new FILE_IO_PRIORITY_HINT_INFO { PriorityHint = IoPriorityHint.VeryLow }; SetFileInformationByHandle(h, FILE_INFO_BY_HANDLE_CLASS.FileIoPriorityHintInfo, ref info, (uint)Marshal.SizeOf<FILE_IO_PRIORITY_HINT_INFO>()); }
        catch { }
    }

    private static SafeFileHandle? GetSafeHandle(Stream s) => s is FileStream fs ? fs.SafeFileHandle : null;

    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetThreadPriority(IntPtr hThread, int nPriority);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
    private const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
    private const int THREAD_MODE_BACKGROUND_BEGIN = 0x00010000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, ref FILE_IO_PRIORITY_HINT_INFO FileInformation, uint dwBufferSize);

    private enum FILE_INFO_BY_HANDLE_CLASS
    { FileBasicInfo = 0, FileIoPriorityHintInfo = 43 }

    private enum IoPriorityHint : uint { VeryLow = 0, Low = 1, Normal = 2 }
    private struct FILE_IO_PRIORITY_HINT_INFO { public IoPriorityHint PriorityHint; }
}

