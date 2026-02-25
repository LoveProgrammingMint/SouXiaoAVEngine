using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;


namespace XPressLineAVHeuristic;

public class XPressLineEntry
{
    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        Console.WriteLine("XPressLine PE Feature Extractor started.");
        Console.WriteLine($"Input Path (PE file or directory): ");
        var inputPath = Console.ReadLine();
        Console.WriteLine($"Output Path (SQLite DB path, or empty for console output): ");
        var dbPath = Console.ReadLine();

        // 如果没有输入数据库路径，直接输出到控制台
        bool consoleOutput = string.IsNullOrWhiteSpace(dbPath);

        if (!consoleOutput)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dbPath)) ?? ".");
        }

        // 判断输入是文件还是目录
        if (File.Exists(inputPath))
        {
            // 单文件处理
            Console.WriteLine($"[+] Processing single file: {inputPath}");
            ProcessSingleFile(inputPath, dbPath, consoleOutput);
        }
        else if (Directory.Exists(inputPath))
        {
            // 目录批量处理
            Console.WriteLine($"[+] Scanning for PE files in: {inputPath}");
            var files = PeCollector.CollectPeImages(inputPath);
            Console.WriteLine($"[+] Found {files.Count} PE files");

            if (files.Count == 0)
            {
                Console.WriteLine("[!] No PE files found.");
                return;
            }

            int success = 0;
            for (int i = 0; i < files.Count; i++)
            {
                Console.WriteLine($"Processing {i + 1}/{files.Count}: {files[i]}");
                try
                {
                    ProcessSingleFile(files[i], dbPath, consoleOutput);
                    success++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[ERROR] {files[i]}: {ex.Message}");
                }
            }

            Console.WriteLine($"[+] Total processed: {success}/{files.Count} files");
        }
        else
        {
            Console.WriteLine($"[!] Path does not exist: {inputPath}");
        }

        Console.WriteLine("Done.");
    }

    private static void ProcessSingleFile(string filePath, string dbPath, bool consoleOutput)
    {
        var extractor = new PEFeatureExtractor(filePath);
        var features = extractor.ExtractAllFeatures();

        if (consoleOutput)
        {
            // 直接输出到控制台，不打标签
            foreach (var f in features.OrderBy(x => x.Key))
            {
                Console.WriteLine($"{f.Key}: {f.Value:F6}");
            }
            Console.WriteLine($"[OK] Extracted {features.Count} features");
        }
        else
        {
            // 保存到数据库，不去重
            SaveToDatabase(filePath, features, dbPath);
            Console.WriteLine($"[OK] Saved {features.Count} features to database");
        }
    }

    private static void SaveToDatabase(string filePath, Dictionary<string, double> features, string dbPath)
    {
        using var conn = new SqliteConnection($"Data Source={dbPath}");
        conn.Open();

        // 创建表
        using var createCmd = new SqliteCommand(@"
            CREATE TABLE IF NOT EXISTS PE_Features (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                FilePath TEXT,
                FeatureName TEXT,
                FeatureValue REAL,
                ExtractTime DATETIME DEFAULT CURRENT_TIMESTAMP
            )", conn);
        createCmd.ExecuteNonQuery();

        // 插入每个特征，不打标签，不去重
        foreach (var f in features)
        {
            using var cmd = new SqliteCommand(@"
                INSERT INTO PE_Features (FilePath, FeatureName, FeatureValue)
                VALUES (@path, @name, @value)", conn);
            cmd.Parameters.AddWithValue("@path", filePath);
            cmd.Parameters.AddWithValue("@name", f.Key);
            cmd.Parameters.AddWithValue("@value", f.Value);
            cmd.ExecuteNonQuery();
        }
    }

    private static List<string> CollectPeFiles(string rootPath)
    {
        var results = new List<string>();

        try
        {
            var files = Directory.EnumerateFiles(rootPath, "*.exe", SearchOption.AllDirectories)
                .Concat(Directory.EnumerateFiles(rootPath, "*.dll", SearchOption.AllDirectories))
                .Concat(Directory.EnumerateFiles(rootPath, "*.sys", SearchOption.AllDirectories));

            foreach (var file in files)
            {
                try
                {
                    if (IsPeFile(file))
                    {
                        results.Add(file);
                        Console.WriteLine($"[FOUND] {file}");
                    }
                }
                catch
                {
                    // 忽略无法访问的文件
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine($"[-] Access denied: {rootPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error in {rootPath}: {ex.Message}");
        }

        return results;
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
