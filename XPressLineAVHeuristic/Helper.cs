using Microsoft.Data.Sqlite;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace XPressLineAVHeuristic
{
    internal class HelperTool
    {
        public static void Run(string[] args)
        {
            Console.WriteLine("Debuger started.");
            Console.WriteLine($"Input Path: ");
            var l = Console.ReadLine();
            Console.WriteLine($"Output Path (SQLite DB path): ");
            var o = Console.ReadLine();

            using var db = new HeadHashDatabase(o);
            db.Initialize();

            Console.WriteLine($"[+] Scanning for PE files in: {l}");
            var all = PeCollector.CollectPeImages(l, recursive: true);

            Console.WriteLine($"[+] Found {all.Count} PE files");

            if (all.Count == 0)
            {
                Console.WriteLine("[!] No PE files found.");
                Console.WriteLine("Press any key to exit.");
                Console.ReadKey();
                return;
            }

            for (int i = 0; i < all.Count; i++)
            {
                Console.WriteLine($"Processing {i + 1}/{all.Count}: {all[i]}");
                try
                {
                    string hash = SaveHeadHash(all[i], db);
                    Console.WriteLine($"[OK] Saved head with hash: {hash}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] {all[i]}: {ex.Message}");
                }
            }

            Console.WriteLine($"[+] Total processed: {db.GetCount()} entries in database");
            Console.WriteLine("Done. Press any key to exit.");
            Console.ReadKey();
        }

        public static string SaveHeadHash(string filePath, HeadHashDatabase db)
        {
            if (string.IsNullOrWhiteSpace(filePath)) throw new ArgumentNullException(nameof(filePath));
            if (db == null) throw new ArgumentNullException(nameof(db));

            const int Length = 3 * 64 * 64;
            byte[] buffer = new byte[Length];

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1, FileOptions.SequentialScan))
            {
                int read = 0;
                while (read < Length)
                {
                    int n = fs.Read(buffer, read, Length - read);
                    if (n <= 0) break;
                    read += n;
                }
            }

            Span<byte> hashSpan = stackalloc byte[32];
            SHA256.HashData(buffer, hashSpan);
            string hashHex = Convert.ToHexString(hashSpan);

            db.Insert(hashHex, buffer, filePath);
            return hashHex;
        }
    }

    public static class PeCollector
    {
        public static List<string> CollectPeImages(string rootPath, bool recursive = true)
        {
            var results = new List<string>();

            if (string.IsNullOrWhiteSpace(rootPath))
            {
                Console.WriteLine("[!] Path is null or empty");
                return results;
            }

            if (!Directory.Exists(rootPath))
            {
                Console.WriteLine($"[!] Directory does not exist: {rootPath}");
                return results;
            }

            Console.WriteLine($"[DEBUG] Starting scan: {rootPath}, recursive={recursive}");
            CollectInternal(rootPath, recursive, results);
            return results;
        }

        private static void CollectInternal(string currentDir, bool recursive, List<string> results)
        {
            try
            {
                var files = Directory.EnumerateFiles(currentDir, "*.*", SearchOption.TopDirectoryOnly);
                foreach (var file in files)
                {
                    if (IsPeFile(file))
                    {
                        results.Add(file);
                        Console.WriteLine($"[FOUND] {file}");
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"[-] Access denied: {currentDir}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error in {currentDir}: {ex.Message}");
            }

            if (!recursive) return;

            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                {
                    CollectInternal(subDir, recursive, results);
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"[-] Access denied (subdir): {currentDir}");
            }
        }

        private static bool IsPeFile(string filePath)
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

                if (fs.Length < 64)
                    return false;

                var dosHeader = new byte[64];
                if (fs.Read(dosHeader, 0, 64) != 64)
                    return false;

                if (dosHeader[0] != 0x4D || dosHeader[1] != 0x5A)
                    return false;

                int peOffset = BitConverter.ToInt32(dosHeader, 0x3C);

                if (peOffset < 0 || peOffset > fs.Length - 4)
                    return false;

                fs.Seek(peOffset, SeekOrigin.Begin);

                var peSig = new byte[4];
                if (fs.Read(peSig, 0, 4) != 4)
                    return false;

                return peSig[0] == 0x50 && peSig[1] == 0x45 && peSig[2] == 0x00 && peSig[3] == 0x00;
            }
            catch
            {
                return false;
            }
        }
    }

    public class HeadHashDatabase : IDisposable
    {
        private readonly SqliteConnection _connection;

        public HeadHashDatabase(string dbPath)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dbPath)) ?? ".");
            _connection = new SqliteConnection($"Data Source={dbPath}");
            _connection.Open();
        }

        public void Initialize()
        {
            using var cmd = _connection.CreateCommand();

            // 删除旧表（如果存在）以确保结构一致，或改用 ALTER TABLE
            // 这里选择：如果表不存在则创建，否则检查并添加缺失列
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS FileHeads (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Hash TEXT UNIQUE NOT NULL,
                    HeadData BLOB NOT NULL,
                    SourcePath TEXT,
                    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS IX_Hash ON FileHeads(Hash);
            ";
            cmd.ExecuteNonQuery();

            // 检查是否需要添加 FileSize 列（如果之前创建的表没有这个列）
            try
            {
                cmd.CommandText = "SELECT FileSize FROM FileHeads LIMIT 1";
                cmd.ExecuteScalar();
            }
            catch (SqliteException)
            {
                // 列不存在，添加它
                cmd.CommandText = "ALTER TABLE FileHeads ADD COLUMN FileSize INTEGER";
                cmd.ExecuteNonQuery();
                Console.WriteLine("[+] Added FileSize column to existing table");
            }

            Console.WriteLine($"[+] Database initialized");
        }

        public void Insert(string hash, byte[] headData, string sourcePath)
        {
            long fileSize = 0;
            try { fileSize = new FileInfo(sourcePath).Length; } catch { }

            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                INSERT OR REPLACE INTO FileHeads (Hash, HeadData, SourcePath, FileSize) 
                VALUES (@hash, @data, @path, @size);
            ";
            cmd.Parameters.AddWithValue("@hash", hash);
            cmd.Parameters.AddWithValue("@data", headData);
            cmd.Parameters.AddWithValue("@path", sourcePath);
            cmd.Parameters.AddWithValue("@size", fileSize);
            cmd.ExecuteNonQuery();
        }

        public int GetCount()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM FileHeads";
            return Convert.ToInt32(cmd.ExecuteScalar());
        }

        public void Dispose()
        {
            _connection?.Dispose();
        }
    }
}