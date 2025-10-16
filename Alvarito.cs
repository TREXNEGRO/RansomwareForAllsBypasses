using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
class Program
{
    // ---------- Constantes ----------
    private static readonly string DefaultFolder = @"C:\\TEST";
    private const int FileVersion = 4;
    private const byte AlgoChunkedGcm = 3;

    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("EBOX");

    private const int SaltSize = 16;         // 128-bit
    private const int GcmNonceSize = 12;     // 96-bit
    private const int GcmTagSize = 16;       // 128-bit
    private const int DefaultChunkSize = 4 * 1024 * 1024; // 4 MiB
    private const int Pbkdf2Iterations = 600_000;

    // TLV meta tipos
    private const byte TLV_OrigLen = 0x01;       // 8 bytes (Int64)
    private const byte TLV_MTimeUtcTicks = 0x02; // 8 bytes (Int64)
    private const byte TLV_CTimeUtcTicks = 0x03; // 8 bytes (Int64)
    private const byte TLV_UserAad = 0x04;       // N bytes (UTF8)

    // Recipient tipos
    private const byte REC_Passphrase = 0x01;    // Wrap DEK con KEK derivada
    private const byte REC_DpapiUser = 0x02;     // Wrap DEK con DPAPI CurrentUser
    private const byte REC_DpapiMachine = 0x03;  // Wrap DEK con DPAPI LocalMachine

    // KDF ids
    private const byte KDF_PBKDF2 = 0x01;
    private const byte KDF_ARGON2ID = 0x02; // via reflection si está el paquete

    // ---------- Opciones CLI ----------
    private class Options
    {
        public string Folder = DefaultFolder;
        public int ChunkSize = DefaultChunkSize;
        public int Threads = Math.Max(1, Environment.ProcessorCount - 1);
        public bool DeletePlaintext = false;
        public bool Yes = false;
        public string Kdf = "pbkdf2"; // pbkdf2 | argon2id
        public HashSet<string> IncludeExt = new();
        public HashSet<string> ExcludeExt = new();
        public string UserAad = string.Empty;
        public bool AddDpapiUser = false;
        public bool AddDpapiMachine = false;
    }

    static void Main(string[] args)
    {
        var opt = ParseArgs(args);
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

        Console.WriteLine($"Archivos: {files.Count} | Chunks: {opt.ChunkSize / (1024 * 1024)} MiB | Hilos: {opt.Threads} | KDF: {opt.Kdf} | DPAPI(user={opt.AddDpapiUser}, machine={opt.AddDpapiMachine})\n");

        object consoleLock = new();
        int ok = 0, err = 0, del = 0;

        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = opt.Threads }, input =>
        {
            try
            {
                string output = input + ".enc";
                string tmp = output + ".tmp";
                var info = new FileInfo(input);

                // 1) Generar DEK aleatoria para el archivo
                byte[] dek = RandomBytes(32);

                // 2) Construir TLV meta
                byte[] tlvMeta = BuildTlvMeta(info, opt.UserAad);

                // 3) Construir tabla de recipients para envolver DEK
                byte[] recipients = BuildRecipients(dek, pass1, opt.Kdf, opt.AddDpapiUser, opt.AddDpapiMachine);

                // 4) Parámetros de stream
                byte[] baseNonce = RandomBytes(GcmNonceSize); // 96-bit base; derivamos por índice
                long totalChunks = ComputeTotalChunks(info.Length, opt.ChunkSize);

                // 5) Construir cabecera (hasta stream params) y hashearla para AAD
                byte[] header = BuildHeader(tlvMeta, recipients, opt.ChunkSize, baseNonce, totalChunks);
                byte[] headerHash = SHA256(header);

                // 6) Escribir cabecera y cifrar por chunks
                using (var outFs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20, FileOptions.SequentialScan))
                {
                    outFs.Write(header, 0, header.Length);
                    EncryptChunksGcm(input, outFs, dek, headerHash, baseNonce, opt.ChunkSize, info.Length, totalChunks);
                }

                // 7) Move atómico
                ReplaceFile(tmp, output);

                // 8) Borrado opcional
                if (opt.DeletePlaintext) { TrySecureDelete(input); System.Threading.Interlocked.Increment(ref del); }

                lock (consoleLock)
                {
                    Console.WriteLine($"[OK] {Path.GetFileName(input)} -> {Path.GetFileName(output)} ({info.Length} bytes, {totalChunks} chunks)");
                }
                System.Threading.Interlocked.Increment(ref ok);

                Array.Clear(dek, 0, dek.Length);
            }
            catch (Exception ex)
            {
                lock (consoleLock) Console.WriteLine($"[ERR] {Path.GetFileName(input)}: {ex.Message}");
                System.Threading.Interlocked.Increment(ref err);
            }
        });

        Console.WriteLine($"\nCompletado. Éxitos: {ok} | Errores: {err} | Borrados: {del}");

        // Descifrado interactivo
        Console.Write("\n¿Descifrar un .enc ahora? (s/n): ");
        if (char.ToLowerInvariant(Console.ReadKey(true).KeyChar) == 's')
        {
            Console.Write("\nRuta del archivo .enc: ");
            string enc = Console.ReadLine()!.Trim('"');
            Console.Write("Salida (Enter=quitar .enc): ");
            string outPath = Console.ReadLine()!;
            if (string.IsNullOrWhiteSpace(outPath))
                outPath = enc.EndsWith(".enc", StringComparison.OrdinalIgnoreCase) ? enc[..^4] : enc + ".dec";

            Console.Write("Contraseña (Enter para intentar DPAPI): ");
            string decPass = ReadPasswordAllowEmpty();
            Console.WriteLine();

            try
            {
                var restored = DecryptAuto(enc, outPath, decPass);
                if (restored.MTimeUtcTicks.HasValue)
                    File.SetLastWriteTimeUtc(outPath, new DateTime(restored.MTimeUtcTicks.Value, DateTimeKind.Utc));
                if (restored.CTimeUtcTicks.HasValue)
                    File.SetCreationTimeUtc(outPath, new DateTime(restored.CTimeUtcTicks.Value, DateTimeKind.Utc));
                Console.WriteLine($"[OK] Descifrado en: {outPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERR] Descifrado: {ex.Message}");
            }
        }
    }

    // ---------- Cifrado por chunks AES-GCM ----------
    private static void EncryptChunksGcm(string inputPath, FileStream outFs, byte[] dek, byte[] headerHash, byte[] baseNonce, int chunkSize, long totalLen, long totalChunks)
    {
        using var inFs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        using var gcm = new AesGcm(dek);

        byte[] plain = new byte[chunkSize];
        byte[] cipher = new byte[chunkSize];
        byte[] tag = new byte[GcmTagSize];
        byte[] aad = new byte[headerHash.Length + sizeof(long)]; // headerHash || chunkIndex(8)
        Buffer.BlockCopy(headerHash, 0, aad, 0, headerHash.Length);

        long idx = 0;
        long remaining = totalLen;
        while (remaining > 0)
        {
            int toRead = (int)Math.Min(chunkSize, remaining);
            int r = ReadExact(inFs, plain, toRead);
            if (r != toRead) throw new EndOfStreamException();

            // Nonce derivada: baseNonce[0..7] || (counter XOR) baseNonce[8..11]
            byte[] nonce = DeriveNonce(baseNonce, idx);

            // AAD = headerHash || idx
            WriteInt64LE(aad, headerHash.Length, idx);

            gcm.Encrypt(nonce, plain.AsSpan(0, toRead), cipher.AsSpan(0, toRead), tag, aad);

            // Escribimos: [CIPHERTEXT (toRead)] [TAG(16)]
            outFs.Write(cipher, 0, toRead);
            outFs.Write(tag, 0, tag.Length);

            remaining -= toRead;
            idx++;
        }
    }

    private static int ReadExact(Stream s, byte[] buf, int count)
    {
        int off = 0;
        while (off < count)
        {
            int r = s.Read(buf, off, count - off);
            if (r <= 0) break;
            off += r;
        }
        return off;
    }

    private static byte[] DeriveNonce(byte[] baseNonce, long idx)
    {
        // 12 bytes: copy base, XOR last 4 bytes with (uint)idx
        byte[] n = new byte[GcmNonceSize];
        Buffer.BlockCopy(baseNonce, 0, n, 0, GcmNonceSize);
        uint c = (uint)idx;
        n[8] ^= (byte)(c & 0xFF);
        n[9] ^= (byte)((c >> 8) & 0xFF);
        n[10] ^= (byte)((c >> 16) & 0xFF);
        n[11] ^= (byte)((c >> 24) & 0xFF);
        return n;
    }

    private static long ComputeTotalChunks(long len, int chunkSize)
    {
        if (len == 0) return 1; // manejar archivo vacío con 1 chunk de 0 bytes
        return (len + chunkSize - 1) / chunkSize;
    }

    // ---------- Decrypt auto ----------
    private class RestoredMeta { public long? MTimeUtcTicks; public long? CTimeUtcTicks; }

    private static RestoredMeta DecryptAuto(string inputPath, string outputPath, string passphrase)
    {
        using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        using var br = new BinaryReader(fs);

        // Magic/Version/Algo
        if (!br.ReadBytes(Magic.Length).SequenceEqual(Magic)) throw new InvalidDataException("MAGIC inválido");
        int ver = br.ReadByte(); if (ver != FileVersion) throw new InvalidDataException($"Versión no soportada: {ver}");
        int algo = br.ReadByte(); if (algo != AlgoChunkedGcm) throw new InvalidDataException($"Algoritmo no soportado: {algo}");

        // TLV meta
        int tlvLen = br.ReadInt32(); if (tlvLen < 0 || tlvLen > 10_000_000) throw new InvalidDataException("TLVLen inválido");
        byte[] tlv = br.ReadBytes(tlvLen);
        var meta = ParseTlv(tlv);

        // Recipients
        int recLen = br.ReadInt32(); if (recLen < 0 || recLen > 10_000_000) throw new InvalidDataException("RecipientsLen inválido");
        byte[] recipients = br.ReadBytes(recLen);

        // Stream params
        int chunkSize = br.ReadInt32(); if (chunkSize <= 0 || chunkSize > (1 << 26)) throw new InvalidDataException("ChunkSize inválido");
        byte[] baseNonce = br.ReadBytes(GcmNonceSize);
        long totalChunks = br.ReadInt64(); if (totalChunks <= 0) throw new InvalidDataException("TotalChunks inválido");
        int reserved = br.ReadInt32(); // ignorado

        // Reconstituir cabecera para headerHash
        byte[] header = BuildHeader(tlv, recipients, chunkSize, baseNonce, totalChunks);
        byte[] headerHash = SHA256(header);

        // 1) Desenvelopar DEK (passphrase y/o DPAPI)
        byte[] dek = UnwrapDek(recipients, passphrase);

        // 2) Descifrar chunks
        using var outFs = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20, FileOptions.SequentialScan);
        using var gcm = new AesGcm(dek);

        long expectedLen = meta.OrigLen ?? throw new InvalidDataException("TLV sin longitud original");
        long remaining = expectedLen;
        long idx = 0;

        byte[] cipher = new byte[chunkSize];
        byte[] plain = new byte[chunkSize];
        byte[] tag = new byte[GcmTagSize];
        byte[] aad = new byte[headerHash.Length + sizeof(long)];
        Buffer.BlockCopy(headerHash, 0, aad, 0, headerHash.Length);

        while (idx < totalChunks)
        {
            int thisLen = (int)Math.Min(chunkSize, remaining > 0 ? remaining : 0);
            if (expectedLen == 0 && idx == 0) thisLen = 0; // archivo vacío
            int toRead = thisLen;
            int r = ReadExact(fs, cipher, toRead);
            if (r != toRead) throw new EndOfStreamException();
            int t = ReadExact(fs, tag, GcmTagSize);
            if (t != GcmTagSize) throw new EndOfStreamException();

            byte[] nonce = DeriveNonce(baseNonce, idx);
            WriteInt64LE(aad, headerHash.Length, idx);

            gcm.Decrypt(nonce, cipher.AsSpan(0, thisLen), tag, plain.AsSpan(0, thisLen), aad);
            if (thisLen > 0) outFs.Write(plain, 0, thisLen);

            remaining -= thisLen;
            idx++;
        }

        Array.Clear(dek, 0, dek.Length);
        return new RestoredMeta { MTimeUtcTicks = meta.MTimeUtcTicks, CTimeUtcTicks = meta.CTimeUtcTicks };
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
                default: break; // ignora TLV desconocidos
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
            // KDF -> KEK
            byte kdfId = kdfName.Equals("argon2id", StringComparison.OrdinalIgnoreCase) ? KDF_ARGON2ID : KDF_PBKDF2;
            byte[] salt = RandomBytes(SaltSize);
            byte[] kek;
            int iterations = Pbkdf2Iterations;
            if (kdfId == KDF_ARGON2ID) kek = DeriveKey(passphrase, salt, 32, kdfName);
            else { kek = DeriveKey(passphrase, salt, 32, kdfName); iterations = Pbkdf2Iterations; }

            byte[] nonce = RandomBytes(GcmNonceSize);
            byte[] wrapped = new byte[dek.Length];
            byte[] tag = new byte[GcmTagSize];
            using (var gcm = new AesGcm(kek)) gcm.Encrypt(nonce, dek, wrapped, tag);

            using var rec = new MemoryStream();
            using (var wr = new BinaryWriter(rec))
            {
                wr.Write((byte)kdfId);                    // 1
                wr.Write(iterations);                     // 4 (para PBKDF2; ignorado en Argon)
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
            byte[] blobUser = addDpapiUser ? ProtectedData.Protect(dek, null, DataProtectionScope.CurrentUser) : Array.Empty<byte>();
            byte[] blobMachine = addDpapiMachine ? ProtectedData.Protect(dek, null, DataProtectionScope.LocalMachine) : Array.Empty<byte>();
            if (addDpapiUser) WriteRecipient(bw, REC_DpapiUser, BuildDpapiPayload(blobUser, 1));
            if (addDpapiMachine) WriteRecipient(bw, REC_DpapiMachine, BuildDpapiPayload(blobMachine, 2));
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
        int i = 0;
        byte[]? dek = null;

        // Primero intentar passphrase si la hay
        if (!string.IsNullOrEmpty(passphrase))
        {
            if (TryUnwrapWithPass(recipients, passphrase, out dek)) return dek!;
            // Si falla, probamos DPAPI
        }
        // Si no hay pass o no funcionó, intentar DPAPI
        if (OperatingSystem.IsWindows())
        {
            if (TryUnwrapWithDpapi(recipients, DataProtectionScope.CurrentUser, out dek)) return dek!;
            if (TryUnwrapWithDpapi(recipients, DataProtectionScope.LocalMachine, out dek)) return dek!;
        }

        throw new CryptographicException("No se pudo desenvelopar la DEK (clave/DPAPI inválidos o entradas ausentes)");
    }

    private static bool TryUnwrapWithPass(byte[] recipients, string passphrase, out byte[]? dek)
    {
        dek = null;
        int i = 0;
        while (i + 5 <= recipients.Length)
        {
            byte type = recipients[i++];
            int len = BitConverter.ToInt32(recipients, i); i += 4;
            if (len < 0 || i + len > recipients.Length) break;
            if (type == REC_Passphrase)
            {
                int off = i;
                byte kdfId = recipients[off++];
                int iterations = BitConverter.ToInt32(recipients, off); off += 4;
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
                if (outDek.Length == 32)
                { dek = outDek; return true; }
            }
            i += len;
        }
        return false;
    }

    private static bool TryUnwrapWithDpapi(byte[] recipients, DataProtectionScope scope, out byte[]? dek)
    {
        dek = null;
        if (!OperatingSystem.IsWindows()) return false;
        int i = 0;
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
                try
                {
                    byte[] outDek = ProtectedData.Unprotect(blob, null, scope);
                    if (outDek.Length == 32) { dek = outDek; return true; }
                }
                catch { /* ignore */ }
            }
            i += len;
        }
        return false;
    }

    // ---------- Utilidades ----------
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
                case "--threads": if (has() && int.TryParse(args[++i], out int t)) o.Threads = Math.Max(1, t); break;
                case "--delete": o.DeletePlaintext = true; break;
                case "--yes": o.Yes = true; break;
                case "--kdf": if (has()) o.Kdf = args[++i]; break;
                case "--include-ext": if (has()) o.IncludeExt = SplitExts(args[++i]); break;
                case "--exclude-ext": if (has()) o.ExcludeExt = SplitExts(args[++i]); break;
                case "--aad": if (has()) o.UserAad = args[++i]; break;
                case "--add-dpapi-user": o.AddDpapiUser = true; break;
                case "--add-dpapi-machine": o.AddDpapiMachine = true; break;
            }
        }
        return o;
    }

    private static HashSet<string> SplitExts(string csv)
    {
        var set = new HashSet<string>();
        foreach (var raw in csv.Split(',', ';', ' ', StringSplitOptions.RemoveEmptyEntries))
        {
            string e = raw.Trim().ToLowerInvariant();
            if (!e.StartsWith('.')) e = "." + e;
            set.Add(e);
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
        try
        {
            var attr = File.GetAttributes(path);
            bool isHidden = (attr & FileAttributes.Hidden) != 0;
            bool isSystem = (attr & FileAttributes.System) != 0;
            return !isHidden && !isSystem;
        }
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
                {
                    int toWrite = (int)Math.Min(zero.Length, left);
                    fs.Write(zero, 0, toWrite);
                    left -= toWrite;
                }
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

    private static byte[] RandomBytes(int len)
    {
        byte[] b = new byte[len];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private static byte[] SHA256(byte[] data)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static void WriteInt64LE(byte[] buf, int offset, long value)
    {
        unchecked
        {
            buf[offset + 0] = (byte)(value & 0xFF);
            buf[offset + 1] = (byte)((value >> 8) & 0xFF);
            buf[offset + 2] = (byte)((value >> 16) & 0xFF);
            buf[offset + 3] = (byte)((value >> 24) & 0xFF);
            buf[offset + 4] = (byte)((value >> 32) & 0xFF);
            buf[offset + 5] = (byte)((value >> 40) & 0xFF);
            buf[offset + 6] = (byte)((value >> 48) & 0xFF);
            buf[offset + 7] = (byte)((value >> 56) & 0xFF);
        }
    }

    private static string ReadPasswordAllowEmpty()
    {
        var sb = new StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Backspace)
            { if (sb.Length > 0) { sb.Length--; Console.Write("\b \b"); } }
            else if (!char.IsControl(k.KeyChar)) { sb.Append(k.KeyChar); Console.Write("*"); }
        }
        return sb.ToString();
    }

    private static string PromptRepeat(string original)
    {
        Console.Write("\nRepite la contraseña: ");
        var again = ReadPasswordAllowEmpty();
        Console.WriteLine();
        if (again != original) { Console.WriteLine("No coincide."); Environment.Exit(1); }
        return again;
    }
}
