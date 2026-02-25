using PeNet;
using PeNet.Header.Pe;
using Microsoft.Data.Sqlite;
using System.Security.Cryptography;

namespace XPressLineAVHeuristic;

public class PEFeatureExtractor
{
    private readonly PeFile _peFile;
    private readonly byte[] _fileData;
    private readonly string _filePath;

    public PEFeatureExtractor(string filePath)
    {
        _filePath = filePath;
        _fileData = File.ReadAllBytes(filePath);
        _peFile = new PeFile(_fileData);
    }

    public PEFeatureExtractor(byte[] fileData, string fileName = "memory")
    {
        _filePath = fileName;
        _fileData = fileData;
        _peFile = new PeFile(_fileData);
    }

    /// <summary>
    /// 提取所有特征并保存到SQLite数据库
    /// </summary>
    public bool ExtractAndSaveToDatabase(string dbPath, bool isMalicious = false, string? fileHash = null)
    {
        try
        {
            var features = ExtractAllFeatures();
            fileHash ??= CalculateFileHash();
            
            using var connection = new SqliteConnection($"Data Source={dbPath}");
            connection.Open();
            
            // 创建表（如果不存在）
            CreateTableIfNotExists(connection);
            
            // 插入特征数据
            InsertFeatures(connection, fileHash, _filePath, features, isMalicious);
            
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"保存到数据库失败: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 提取所有特征（不限制维度）
    /// </summary>
    public Dictionary<string, double> ExtractAllFeatures()
    {
        var features = new Dictionary<string, double>();
        
        // 1. 基础文件特征
        ExtractBasicFileFeatures(features);
        
        // 2. DOS头特征
        ExtractDosHeaderFeatures(features);
        
        // 3. NT头特征
        ExtractNtHeaderFeatures(features);
        
        // 4. 文件头特征
        ExtractFileHeaderFeatures(features);
        
        // 5. 可选头特征
        ExtractOptionalHeaderFeatures(features);
        
        // 6. 节区特征
        ExtractSectionFeatures(features);
        
        // 7. 导入表特征
        ExtractImportFeatures(features);
        
        // 8. 导出表特征
        ExtractExportFeatures(features);
        
        // 9. 资源特征
        ExtractResourceFeatures(features);
        
        // 10. 熵特征
        ExtractEntropyFeatures(features);
        
        // 11. 字节分布特征
        ExtractByteDistributionFeatures(features);
        
        // 12. 字符串特征
        ExtractStringFeatures(features);
        
        // 13. TLS回调特征
        ExtractTlsFeatures(features);
        
        // 14. 重定位特征
        ExtractRelocationFeatures(features);
        
        // 15. 调试信息特征
        ExtractDebugFeatures(features);
        
        return features;
    }

    /// <summary>
    /// 提取特征向量（用于ML模型）
    /// </summary>
    public double[] ExtractFeatureVector()
    {
        var features = ExtractAllFeatures();
        return features.Values.ToArray();
    }

    private void CreateTableIfNotExists(SqliteConnection connection)
    {
        var createTableSql = @"
            CREATE TABLE IF NOT EXISTS PE_Features (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                FileHash TEXT UNIQUE NOT NULL,
                FilePath TEXT,
                ExtractTime DATETIME DEFAULT CURRENT_TIMESTAMP,
                IsMalicious INTEGER,
                FeatureCount INTEGER,
                FeatureData TEXT,
                FileSize INTEGER,
                FileEntropy REAL
            );
            
            CREATE INDEX IF NOT EXISTS idx_hash ON PE_Features(FileHash);
            CREATE INDEX IF NOT EXISTS idx_malicious ON PE_Features(IsMalicious);
        ";
        
        using var command = new SqliteCommand(createTableSql, connection);
        command.ExecuteNonQuery();
    }

    private void InsertFeatures(SqliteConnection connection, string fileHash, string filePath, 
        Dictionary<string, double> features, bool isMalicious)
    {
        // 将特征字典序列化为JSON
        var featureJson = System.Text.Json.JsonSerializer.Serialize(features);
        var fileEntropy = CalculateEntropy(_fileData);
        
        var insertSql = @"
            INSERT OR REPLACE INTO PE_Features 
            (FileHash, FilePath, IsMalicious, FeatureCount, FeatureData, FileSize, FileEntropy)
            VALUES (@hash, @path, @malicious, @count, @data, @size, @entropy)
        ";
        
        using var command = new SqliteCommand(insertSql, connection);
        command.Parameters.AddWithValue("@hash", fileHash);
        command.Parameters.AddWithValue("@path", filePath);
        command.Parameters.AddWithValue("@malicious", isMalicious ? 1 : 0);
        command.Parameters.AddWithValue("@count", features.Count);
        command.Parameters.AddWithValue("@data", featureJson);
        command.Parameters.AddWithValue("@size", _fileData.Length);
        command.Parameters.AddWithValue("@entropy", fileEntropy);
        
        command.ExecuteNonQuery();
    }

    private string CalculateFileHash()
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(_fileData);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    #region 特征提取方法

    private void ExtractBasicFileFeatures(Dictionary<string, double> features)
    {
        features["file_size"] = _fileData.Length;
        features["file_entropy"] = CalculateEntropy(_fileData);
        features["is_pe"] = _peFile.ImageNtHeaders != null ? 1 : 0;
        features["is_32bit"] = _peFile.Is32Bit ? 1 : 0;
        features["is_64bit"] = _peFile.Is64Bit ? 1 : 0;
        features["is_dll"] = _peFile.IsDll ? 1 : 0;
        features["is_exe"] = _peFile.IsExe ? 1 : 0;
        features["is_driver"] = IsDriver() ? 1 : 0;
    }

    private void ExtractDosHeaderFeatures(Dictionary<string, double> features)
    {
        var dosHeader = _peFile.ImageDosHeader;
        if (dosHeader == null) return;

        features["dos_magic"] = dosHeader.E_magic;
        features["dos_cblp"] = dosHeader.E_cblp;
        features["dos_cp"] = dosHeader.E_cp;
        features["dos_crlc"] = dosHeader.E_crlc;
        features["dos_cparhdr"] = dosHeader.E_cparhdr;
        features["dos_minalloc"] = dosHeader.E_minalloc;
        features["dos_maxalloc"] = dosHeader.E_maxalloc;
        features["dos_ss"] = dosHeader.E_ss;
        features["dos_sp"] = dosHeader.E_sp;
        features["dos_csum"] = dosHeader.E_csum;
        features["dos_ip"] = dosHeader.E_ip;
        features["dos_cs"] = dosHeader.E_cs;
        features["dos_lfarlc"] = dosHeader.E_lfarlc;
        features["dos_ovno"] = dosHeader.E_ovno;
        features["dos_lfanew"] = dosHeader.E_lfanew;
        features["dos_header_entropy"] = CalculateEntropy(_fileData.Take(64).ToArray());
    }

    private void ExtractNtHeaderFeatures(Dictionary<string, double> features)
    {
        var ntHeaders = _peFile.ImageNtHeaders;
        if (ntHeaders == null) return;

        features["nt_signature"] = ntHeaders.Signature;
        features["nt_header_entropy"] = CalculateEntropy(_fileData.Skip((int)_peFile.ImageDosHeader.E_lfanew).Take(24).ToArray());
    }

    private void ExtractFileHeaderFeatures(Dictionary<string, double> features)
    {
        var fileHeader = _peFile.ImageNtHeaders?.FileHeader;
        if (fileHeader == null) return;

        features["file_machine"] = (ushort)fileHeader.Machine;
        features["file_num_sections"] = fileHeader.NumberOfSections;
        features["file_timestamp"] = fileHeader.TimeDateStamp;
        features["file_sym_table_ptr"] = fileHeader.PointerToSymbolTable;
        features["file_num_symbols"] = fileHeader.NumberOfSymbols;
        features["file_opt_header_size"] = fileHeader.SizeOfOptionalHeader;
        features["file_characteristics"] = (ushort)fileHeader.Characteristics;
        
        // 特性标志位
        var chars = (ushort)fileHeader.Characteristics;
        features["file_char_relocs_stripped"] = (chars & 0x0001) != 0 ? 1 : 0;
        features["file_char_executable"] = (chars & 0x0002) != 0 ? 1 : 0;
        features["file_char_line_nums_stripped"] = (chars & 0x0004) != 0 ? 1 : 0;
        features["file_char_local_syms_stripped"] = (chars & 0x0008) != 0 ? 1 : 0;
        features["file_char_large_address"] = (chars & 0x0020) != 0 ? 1 : 0;
        features["file_char_32bit"] = (chars & 0x0100) != 0 ? 1 : 0;
        features["file_char_debug_stripped"] = (chars & 0x0200) != 0 ? 1 : 0;
        features["file_char_removable_run"] = (chars & 0x0400) != 0 ? 1 : 0;
        features["file_char_net_run"] = (chars & 0x0800) != 0 ? 1 : 0;
        features["file_char_system"] = (chars & 0x1000) != 0 ? 1 : 0;
        features["file_char_dll"] = (chars & 0x2000) != 0 ? 1 : 0;
        features["file_char_up_only"] = (chars & 0x4000) != 0 ? 1 : 0;
        features["file_char_bytes_reversed_hi"] = (chars & 0x8000) != 0 ? 1 : 0;
    }

    private void ExtractOptionalHeaderFeatures(Dictionary<string, double> features)
    {
        var optionalHeader = _peFile.ImageNtHeaders?.OptionalHeader;
        if (optionalHeader == null) return;

        features["opt_magic"] = (ushort)optionalHeader.Magic;
        features["opt_major_linker"] = optionalHeader.MajorLinkerVersion;
        features["opt_minor_linker"] = optionalHeader.MinorLinkerVersion;
        features["opt_code_size"] = optionalHeader.SizeOfCode;
        features["opt_init_data_size"] = optionalHeader.SizeOfInitializedData;
        features["opt_uninit_data_size"] = optionalHeader.SizeOfUninitializedData;
        features["opt_entry_point"] = optionalHeader.AddressOfEntryPoint;
        features["opt_base_of_code"] = optionalHeader.BaseOfCode;
        features["opt_base_of_data"] = _peFile.Is32Bit ? optionalHeader.BaseOfData : 0;
        features["opt_image_base"] = (ulong)optionalHeader.ImageBase;
        features["opt_section_align"] = optionalHeader.SectionAlignment;
        features["opt_file_align"] = optionalHeader.FileAlignment;
        features["opt_major_os"] = optionalHeader.MajorOperatingSystemVersion;
        features["opt_minor_os"] = optionalHeader.MinorOperatingSystemVersion;
        features["opt_major_image"] = optionalHeader.MajorImageVersion;
        features["opt_minor_image"] = optionalHeader.MinorImageVersion;
        features["opt_major_subsystem"] = optionalHeader.MajorSubsystemVersion;
        features["opt_minor_subsystem"] = optionalHeader.MinorSubsystemVersion;
        features["opt_win32_version"] = optionalHeader.Win32VersionValue;
        features["opt_image_size"] = optionalHeader.SizeOfImage;
        features["opt_headers_size"] = optionalHeader.SizeOfHeaders;
        features["opt_checksum"] = optionalHeader.CheckSum;
        features["opt_subsystem"] = (ushort)optionalHeader.Subsystem;
        features["opt_dll_characteristics"] = (ushort)optionalHeader.DllCharacteristics;
        features["opt_stack_reserve"] = (ulong)optionalHeader.SizeOfStackReserve;
        features["opt_stack_commit"] = (ulong)optionalHeader.SizeOfStackCommit;
        features["opt_heap_reserve"] = (ulong)optionalHeader.SizeOfHeapReserve;
        features["opt_heap_commit"] = (ulong)optionalHeader.SizeOfHeapCommit;
        features["opt_loader_flags"] = optionalHeader.LoaderFlags;
        features["opt_num_rva"] = optionalHeader.NumberOfRvaAndSizes;
        
        // 数据目录
        var dataDirs = optionalHeader.DataDirectory;
        if (dataDirs != null)
        {
            for (int i = 0; i < Math.Min(dataDirs.Length, 16); i++)
            {
                features[$"opt_data_dir_{i}_rva"] = dataDirs[i].VirtualAddress;
                features[$"opt_data_dir_{i}_size"] = dataDirs[i].Size;
            }
        }
    }

    private void ExtractSectionFeatures(Dictionary<string, double> features)
    {
        var sections = _peFile.ImageSectionHeaders;
        if (sections == null || sections.Length == 0) return;

        features["section_count"] = sections.Length;
        
        // 统计各类型节区
        int textCount = 0, dataCount = 0, rsrcCount = 0, codeCount = 0;
        double totalVirtualSize = 0, totalRawSize = 0;
        double maxEntropy = 0, minEntropy = double.MaxValue, avgEntropy = 0;
        int executableSections = 0, writableSections = 0, readableSections = 0;
        
        var entropies = new List<double>();
        
        foreach (var section in sections)
        {
            var name = section.Name?.ToLower() ?? "";
            if (name.Contains(".text")) textCount++;
            if (name.Contains(".data")) dataCount++;
            if (name.Contains(".rsrc")) rsrcCount++;
            if (name.Contains("code")) codeCount++;
            
            totalVirtualSize += section.VirtualSize;
            totalRawSize += section.SizeOfRawData;
            
            var chars = (uint)section.Characteristics;
            if ((chars & 0x20000000) != 0) executableSections++;
            if ((chars & 0x80000000) != 0) writableSections++;
            if ((chars & 0x40000000) != 0) readableSections++;
            
            // 计算节区熵
            if (section.SizeOfRawData > 0)
            {
                var offset = (int)section.PointerToRawData;
                var size = (int)Math.Min(section.SizeOfRawData, _fileData.Length - offset);
                if (size > 0 && offset >= 0)
                {
                    var sectionData = new byte[size];
                    Array.Copy(_fileData, offset, sectionData, 0, size);
                    var entropy = CalculateEntropy(sectionData);
                    entropies.Add(entropy);
                    maxEntropy = Math.Max(maxEntropy, entropy);
                    minEntropy = Math.Min(minEntropy, entropy);
                }
            }
        }
        
        features["section_text_count"] = textCount;
        features["section_data_count"] = dataCount;
        features["section_rsrc_count"] = rsrcCount;
        features["section_code_count"] = codeCount;
        features["section_total_virtual_size"] = totalVirtualSize;
        features["section_total_raw_size"] = totalRawSize;
        features["section_size_ratio"] = totalRawSize > 0 ? totalVirtualSize / totalRawSize : 0;
        features["section_executable_count"] = executableSections;
        features["section_writable_count"] = writableSections;
        features["section_readable_count"] = readableSections;
        features["section_max_entropy"] = entropies.Count > 0 ? maxEntropy : 0;
        features["section_min_entropy"] = entropies.Count > 0 ? minEntropy : 0;
        features["section_avg_entropy"] = entropies.Count > 0 ? entropies.Average() : 0;
        features["section_entropy_std"] = entropies.Count > 1 ? CalculateStdDev(entropies) : 0;
    }

    private void ExtractImportFeatures(Dictionary<string, double> features)
    {
        var imports = _peFile.ImportedFunctions;
        if (imports == null || imports.Length == 0)
        {
            features["import_count"] = 0;
            features["import_dll_count"] = 0;
            return;
        }

        features["import_count"] = imports.Length;
        
        var importsByDll = imports.GroupBy(i => i.DLL).ToArray();
        features["import_dll_count"] = importsByDll.Length;
        
        // 每个DLL的导入数量统计
        var importsPerDll = importsByDll.Select(g => (double)g.Count()).ToArray();
        features["import_per_dll_max"] = importsPerDll.Length > 0 ? importsPerDll.Max() : 0;
        features["import_per_dll_min"] = importsPerDll.Length > 0 ? importsPerDll.Min() : 0;
        features["import_per_dll_avg"] = importsPerDll.Length > 0 ? importsPerDll.Average() : 0;
        features["import_per_dll_std"] = importsPerDll.Length > 1 ? CalculateStdDev(importsPerDll.ToList()) : 0;
        
        // 常见DLL检测
        var commonDlls = new[] { "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll", 
                                 "ole32.dll", "oleaut32.dll", "ntdll.dll", "ws2_32.dll", "comctl32.dll",
                                 "msvcrt.dll", "shlwapi.dll", "gdiplus.dll", "crypt32.dll", "wininet.dll" };
        
        foreach (var dll in commonDlls)
        {
            var dllName = dll.Replace(".dll", "").Replace("32", "");
            features[$"import_has_{dllName}"] = importsByDll.Any(g => 
                g.Key?.Equals(dll, StringComparison.OrdinalIgnoreCase) == true) ? 1 : 0;
        }
        
        // API名称分析
        var apiNames = imports.Select(i => i.Name?.ToLower() ?? "").ToArray();
        features["import_api_avg_length"] = apiNames.Length > 0 ? apiNames.Average(n => n.Length) : 0;
        features["import_api_max_length"] = apiNames.Length > 0 ? apiNames.Max(n => n.Length) : 0;
        features["import_api_min_length"] = apiNames.Length > 0 ? apiNames.Min(n => n.Length) : 0;
        features["import_api_with_a"] = apiNames.Count(n => n.EndsWith("a"));
        features["import_api_with_w"] = apiNames.Count(n => n.EndsWith("w"));
        features["import_api_with_ex"] = apiNames.Count(n => n.Contains("ex"));
        features["import_api_with_nt"] = apiNames.Count(n => n.StartsWith("nt"));
        features["import_api_with_zw"] = apiNames.Count(n => n.StartsWith("zw"));
        features["import_api_with_rtl"] = apiNames.Count(n => n.StartsWith("rtl"));
    }

    private void ExtractExportFeatures(Dictionary<string, double> features)
    {
        var exports = _peFile.ExportedFunctions;
        if (exports == null || exports.Length == 0)
        {
            features["export_count"] = 0;
            return;
        }

        features["export_count"] = exports.Length;
        
        var exportRvas = exports.Select(e => (double)e.Address).ToArray();
        features["export_rva_max"] = exportRvas.Max();
        features["export_rva_min"] = exportRvas.Min();
        features["export_rva_avg"] = exportRvas.Average();
        features["export_rva_std"] = exportRvas.Length > 1 ? CalculateStdDev(exportRvas.ToList()) : 0;
        
        var exportOrdinals = exports.Select(e => (double)e.Ordinal).ToArray();
        features["export_ordinal_max"] = exportOrdinals.Max();
        features["export_ordinal_min"] = exportOrdinals.Min();
        features["export_ordinal_avg"] = exportOrdinals.Average();
        
        // 导出函数名称分析
        var exportNames = exports.Select(e => e.Name?.ToLower() ?? "").ToArray();
        features["export_name_avg_length"] = exportNames.Length > 0 ? exportNames.Average(n => n.Length) : 0;
        features["export_with_underscore"] = exportNames.Count(n => n.StartsWith("_"));
        features["export_with_at"] = exportNames.Count(n => n.Contains("@"));
    }

    private void ExtractResourceFeatures(Dictionary<string, double> features)
    {
        var resources = _peFile.Resources;
        if (resources == null)
        {
            features["resource_count"] = 0;
            return;
        }

        int resourceCount = 0;
        if (resources.Icons != null) resourceCount += resources.Icons.Length;
        
        features["resource_count"] = resourceCount;
        features["resource_icon_count"] = resources.Icons?.Length ?? 0;
        features["resource_has_icon"] = resources.Icons != null && resources.Icons.Length > 0 ? 1 : 0;
        // 检查版本信息和清单资源
        bool hasVersion = false, hasManifest = false;
        try
        {
            // 通过其他方式检测版本信息
            hasVersion = resources.Icons != null && resources.Icons.Length > 0;
        }
        catch { }
        features["resource_has_version"] = hasVersion ? 1 : 0;
        features["resource_has_manifest"] = hasManifest ? 1 : 0;
    }

    private void ExtractEntropyFeatures(Dictionary<string, double> features)
    {
        // 整体熵已在基础特征中提取
        
        // 头部熵
        features["entropy_header"] = CalculateEntropy(_fileData.Take(1024).ToArray());
        
        // 代码段熵
        var textSection = _peFile.ImageSectionHeaders?.FirstOrDefault(s => 
            s.Name?.Contains(".text", StringComparison.OrdinalIgnoreCase) == true);
        if (textSection != null && textSection.SizeOfRawData > 0)
        {
            var offset = (int)textSection.PointerToRawData;
            var size = (int)Math.Min(textSection.SizeOfRawData, _fileData.Length - offset);
            if (size > 0 && offset >= 0)
            {
                var textData = new byte[size];
                Array.Copy(_fileData, offset, textData, 0, size);
                features["entropy_text_section"] = CalculateEntropy(textData);
            }
        }
        
        // 数据段熵
        var dataSection = _peFile.ImageSectionHeaders?.FirstOrDefault(s => 
            s.Name?.Contains(".data", StringComparison.OrdinalIgnoreCase) == true);
        if (dataSection != null && dataSection.SizeOfRawData > 0)
        {
            var offset = (int)dataSection.PointerToRawData;
            var size = (int)Math.Min(dataSection.SizeOfRawData, _fileData.Length - offset);
            if (size > 0 && offset >= 0)
            {
                var dataSec = new byte[size];
                Array.Copy(_fileData, offset, dataSec, 0, size);
                features["entropy_data_section"] = CalculateEntropy(dataSec);
            }
        }
    }

    private void ExtractByteDistributionFeatures(Dictionary<string, double> features)
    {
        var byteCounts = new long[256];
        foreach (var b in _fileData)
        {
            byteCounts[b]++;
        }

        var byteFreq = byteCounts.Select(c => (double)c / _fileData.Length).ToArray();
        
        // 基础统计
        features["byte_freq_max"] = byteFreq.Max();
        features["byte_freq_min"] = byteFreq.Min();
        features["byte_freq_avg"] = byteFreq.Average();
        features["byte_freq_std"] = CalculateStdDev(byteFreq.ToList());
        
        // 特定字节
        features["byte_count_zero"] = byteCounts[0];
        features["byte_count_ff"] = byteCounts[0xFF];
        features["byte_count_7f"] = byteCounts[0x7F];
        features["byte_count_4d"] = byteCounts[0x4D]; // 'M'
        features["byte_count_5a"] = byteCounts[0x5A]; // 'Z'
        features["byte_count_50"] = byteCounts[0x50]; // 'P'
        features["byte_count_45"] = byteCounts[0x45]; // 'E'
        
        // 可打印字符
        var printableCount = byteCounts.Skip(32).Take(95).Sum();
        features["byte_printable_ratio"] = printableCount / (double)_fileData.Length;
        
        // 高字节和低字节
        features["byte_high_ratio"] = byteCounts.Skip(128).Sum() / (double)_fileData.Length;
        features["byte_low_ratio"] = byteCounts.Take(128).Sum() / (double)_fileData.Length;
        
        // 字节直方图（16个桶）
        for (int i = 0; i < 16; i++)
        {
            var bucketSum = byteFreq.Skip(i * 16).Take(16).Sum();
            features[$"byte_bucket_{i}"] = bucketSum;
        }
    }

    private void ExtractStringFeatures(Dictionary<string, double> features)
    {
        // 提取可打印字符串
        var strings = ExtractStrings(_fileData, 4);
        
        features["string_count"] = strings.Count;
        features["string_total_length"] = strings.Sum(s => s.Length);
        features["string_avg_length"] = strings.Count > 0 ? strings.Average(s => s.Length) : 0;
        features["string_max_length"] = strings.Count > 0 ? strings.Max(s => s.Length) : 0;
        
        // URL和路径检测
        features["string_url_count"] = strings.Count(s => 
            s.Contains("http://") || s.Contains("https://") || s.Contains("www."));
        features["string_path_count"] = strings.Count(s => 
            s.Contains("\\") || s.Contains("C:\\") || s.Contains("Program Files"));
        features["string_registry_count"] = strings.Count(s => 
            s.Contains("HKEY_") || s.Contains("Registry"));
        
        // API相关字符串
        features["string_dll_count"] = strings.Count(s => s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
        features["string_exe_count"] = strings.Count(s => s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
    }

    private void ExtractTlsFeatures(Dictionary<string, double> features)
    {
        var tlsDir = _peFile.ImageTlsDirectory;
        features["has_tls"] = tlsDir != null ? 1 : 0;
        features["tls_callback_count"] = tlsDir?.AddressOfCallBacks != 0 ? 1 : 0;
    }

    private void ExtractRelocationFeatures(Dictionary<string, double> features)
    {
        var relocDir = _peFile.ImageRelocationDirectory;
        features["has_relocation"] = relocDir != null && relocDir.Length > 0 ? 1 : 0;
        features["relocation_count"] = relocDir?.Length ?? 0;
    }

    private void ExtractDebugFeatures(Dictionary<string, double> features)
    {
        var debugDir = _peFile.ImageDebugDirectory;
        features["has_debug"] = debugDir != null && debugDir.Length > 0 ? 1 : 0;
        features["debug_count"] = debugDir?.Length ?? 0;
        
        if (debugDir != null && debugDir.Length > 0)
        {
            features["debug_type"] = (uint)debugDir[0].Type;
            features["debug_size"] = debugDir[0].SizeOfData;
        }
    }

    #endregion

    #region 辅助方法

    private double CalculateEntropy(byte[] data)
    {
        if (data == null || data.Length == 0) return 0;

        var counts = new int[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        var entropy = 0.0;
        var length = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (counts[i] > 0)
            {
                var p = (double)counts[i] / length;
                entropy -= p * Math.Log2(p);
            }
        }

        return entropy / 8.0;
    }

    private double CalculateStdDev(List<double> values)
    {
        if (values == null || values.Count < 2) return 0;
        var avg = values.Average();
        var sumSquares = values.Sum(v => (v - avg) * (v - avg));
        return Math.Sqrt(sumSquares / values.Count);
    }

    private bool IsDriver()
    {
        var optionalHeader = _peFile.ImageNtHeaders?.OptionalHeader;
        if (optionalHeader == null) return false;
        return (ushort)optionalHeader.Subsystem == 1; // NATIVE
    }

    private List<string> ExtractStrings(byte[] data, int minLength)
    {
        var strings = new List<string>();
        var currentString = new System.Text.StringBuilder();
        
        foreach (var b in data)
        {
            if (b >= 32 && b <= 126) // 可打印ASCII
            {
                currentString.Append((char)b);
            }
            else
            {
                if (currentString.Length >= minLength)
                {
                    strings.Add(currentString.ToString());
                }
                currentString.Clear();
            }
        }
        
        if (currentString.Length >= minLength)
        {
            strings.Add(currentString.ToString());
        }
        
        return strings;
    }

    #endregion
}
