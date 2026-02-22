using PeNet;
using PeNet.Header.Pe;

namespace XPressLineAVHeuristic;

public class PEFeatureExtractor
{
    private PeFile? _peFile;
    private byte[] _fileData = [];
    private string _filePath = String.Empty;



    public double[] ExtractFeatures(string filePath)
    {
        _filePath = filePath;
        _fileData = File.ReadAllBytes(filePath);
        _peFile = new PeFile(_fileData);

        var features = new List<double>();

        // 1. DOS Header: 16
        features.AddRange(ExtractDosHeaderFeatures());
        
        // 2. NT Header: 2
        features.AddRange(ExtractNtHeaderFeatures());
        
        // 3. File Header: 12
        features.AddRange(ExtractFileHeaderFeatures());
        
        // 4. Optional Header: 30
        features.AddRange(ExtractOptionalHeaderFeatures());
        
        // 5. Section Features: 49
        features.AddRange(ExtractSectionFeatures());
        
        // 6. Import Features: 32
        features.AddRange(ExtractImportFeaturesEnhanced());
        
        // 7. Export Features: 16
        features.AddRange(ExtractExportFeaturesEnhanced());
        
        // 8. Resource Features: 16
        features.AddRange(ExtractResourceFeatures());
        
        // 9. Entropy Features: 18
        features.AddRange(ExtractEntropyFeaturesEnhanced());
        
        // 10. Byte Distribution: 65
        features.AddRange(ExtractByteDistributionFeatures());

        if (features.Count != 256)
        {
            throw new InvalidOperationException($"Feature dimension mismatch: expected 256, got {features.Count}");
        }

        return AmplifyFeatures([.. features]);
    }

    private static double[] AmplifyFeatures(double[] features)
    {
        var amplified = new double[features.Length];
        for (int i = 0; i < features.Length; i++)
        {
            var value = features[i];
            if (value < 0.001)
            {
                amplified[i] = value * 1000;
            }
            else if (value < 0.01)
            {
                amplified[i] = value * 100;
            }
            else if (value < 0.1)
            {
                amplified[i] = value * 10;
            }
            else
            {
                amplified[i] = value;
            }
            amplified[i] = Math.Min(amplified[i], 1.0);
        }
        return amplified;
    }

    private double[] ExtractDosHeaderFeatures()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var dosHeader = _peFile.ImageDosHeader;

        if (dosHeader == null)
        {
            return new double[16];
        }

        features.Add(Normalize(dosHeader.E_magic, 0, 65535));
        features.Add(Normalize(dosHeader.E_cblp, 0, 65535));
        features.Add(Normalize(dosHeader.E_cp, 0, 65535));
        features.Add(Normalize(dosHeader.E_crlc, 0, 65535));
        features.Add(Normalize(dosHeader.E_cparhdr, 0, 65535));
        features.Add(Normalize(dosHeader.E_minalloc, 0, 65535));
        features.Add(Normalize(dosHeader.E_maxalloc, 0, 65535));
        features.Add(Normalize(dosHeader.E_ss, 0, 65535));
        features.Add(Normalize(dosHeader.E_sp, 0, 65535));
        features.Add(Normalize(dosHeader.E_csum, 0, 65535));
        features.Add(Normalize(dosHeader.E_ip, 0, 65535));
        features.Add(Normalize(dosHeader.E_cs, 0, 65535));
        features.Add(Normalize(dosHeader.E_lfarlc, 0, 65535));
        features.Add(Normalize(dosHeader.E_ovno, 0, 65535));
        features.Add(Normalize(dosHeader.E_lfanew, 0, int.MaxValue));
        features.Add(dosHeader.E_res?.Length > 0 ? Normalize(dosHeader.E_res.Average(x => x), 0, 65535) : 0);

        return [.. features];
    }

    private double[] ExtractNtHeaderFeatures()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var ntHeaders = _peFile.ImageNtHeaders;

        if (ntHeaders == null)
        {
            return new double[2];
        }

        features.Add(Normalize(ntHeaders.Signature, 0, uint.MaxValue));
        features.Add(Normalize(_peFile.Is32Bit ? 0 : 1, 0, 1));

        return [.. features];
    }

    private double[] ExtractFileHeaderFeatures()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var fileHeader = _peFile.ImageNtHeaders?.FileHeader;

        if (fileHeader == null)
        {
            return new double[12];
        }

        features.Add(Normalize((ushort)fileHeader.Machine, 0, 65535));
        features.Add(Normalize(fileHeader.NumberOfSections, 0, 100));
        features.Add(Normalize(fileHeader.TimeDateStamp, 0, uint.MaxValue));
        features.Add(Normalize(fileHeader.PointerToSymbolTable, 0, uint.MaxValue));
        features.Add(Normalize(fileHeader.NumberOfSymbols, 0, uint.MaxValue));
        features.Add(Normalize(fileHeader.SizeOfOptionalHeader, 0, 65535));
        features.Add(Normalize((ushort)fileHeader.Characteristics, 0, 65535));

        var charBits = new double[5];
        var chars = (ushort)fileHeader.Characteristics;
        charBits[0] = (chars & 0x0002) != 0 ? 1 : 0;
        charBits[1] = (chars & 0x0020) != 0 ? 1 : 0;
        charBits[2] = (chars & 0x2000) != 0 ? 1 : 0;
        charBits[3] = (chars & 0x4000) != 0 ? 1 : 0;
        charBits[4] = (chars & 0x8000) != 0 ? 1 : 0;
        features.AddRange(charBits);

        return features.ToArray();
    }

    private double[] ExtractOptionalHeaderFeatures()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var optionalHeader = _peFile.ImageNtHeaders?.OptionalHeader;

        if (optionalHeader == null)
        {
            return new double[30];
        }

        features.Add(Normalize((ushort)optionalHeader.Magic, 0, 65535));
        features.Add(Normalize(optionalHeader.MajorLinkerVersion, 0, 255));
        features.Add(Normalize(optionalHeader.MinorLinkerVersion, 0, 255));
        features.Add(Normalize(optionalHeader.SizeOfCode, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.SizeOfInitializedData, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.SizeOfUninitializedData, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.AddressOfEntryPoint, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.BaseOfCode, 0, uint.MaxValue));

        if (_peFile.Is32Bit)
        {
            features.Add(Normalize(optionalHeader.BaseOfData, 0, uint.MaxValue));
            features.Add(Normalize((ulong)optionalHeader.ImageBase, 0, uint.MaxValue));
        }
        else
        {
            features.Add(0);
            features.Add(Normalize((ulong)optionalHeader.ImageBase, 0, ulong.MaxValue));
        }

        features.Add(Normalize(optionalHeader.SectionAlignment, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.FileAlignment, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.MajorOperatingSystemVersion, 0, 65535));
        features.Add(Normalize(optionalHeader.MinorOperatingSystemVersion, 0, 65535));
        features.Add(Normalize(optionalHeader.MajorImageVersion, 0, 65535));
        features.Add(Normalize(optionalHeader.MinorImageVersion, 0, 65535));
        features.Add(Normalize(optionalHeader.MajorSubsystemVersion, 0, 65535));
        features.Add(Normalize(optionalHeader.MinorSubsystemVersion, 0, 65535));
        features.Add(Normalize(optionalHeader.Win32VersionValue, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.SizeOfImage, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.SizeOfHeaders, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.CheckSum, 0, uint.MaxValue));
        features.Add(Normalize((ushort)optionalHeader.Subsystem, 0, 65535));
        features.Add(Normalize((ushort)optionalHeader.DllCharacteristics, 0, 65535));
        features.Add(Normalize((ulong)optionalHeader.SizeOfStackReserve, 0, uint.MaxValue));
        features.Add(Normalize((ulong)optionalHeader.SizeOfStackCommit, 0, uint.MaxValue));
        features.Add(Normalize((ulong)optionalHeader.SizeOfHeapReserve, 0, uint.MaxValue));
        features.Add(Normalize((ulong)optionalHeader.SizeOfHeapCommit, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.LoaderFlags, 0, uint.MaxValue));
        features.Add(Normalize(optionalHeader.NumberOfRvaAndSizes, 0, uint.MaxValue));

        return [.. features];
    }

    private double[] ExtractSectionFeatures()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var sections = _peFile.ImageSectionHeaders;

        if (sections == null || sections.Length == 0)
        {
            return new double[49];
        }

        var sectionCount = sections.Length;
        features.Add(Normalize(sectionCount, 0, 100));

        var virtualSizes = sections.Select(s => (double)s.VirtualSize).ToArray();
        var rawSizes = sections.Select(s => (double)s.SizeOfRawData).ToArray();
        var virtualAddresses = sections.Select(s => (double)s.VirtualAddress).ToArray();
        var rawAddresses = sections.Select(s => (double)s.PointerToRawData).ToArray();
        var characteristics = sections.Select(s => (double)s.Characteristics).ToArray();

        features.AddRange(CalculateStatistics(virtualSizes, 8));
        features.AddRange(CalculateStatistics(rawSizes, 8));
        features.AddRange(CalculateStatistics(virtualAddresses, 8));
        features.AddRange(CalculateStatistics(rawAddresses, 8));
        features.AddRange(CalculateStatistics(characteristics, 8));

        var nameFeatures = new double[8];
        var commonSections = new[] { ".text", ".data", ".rsrc", ".rdata", ".bss", ".idata", ".edata", ".reloc" };
        for (int i = 0; i < Math.Min(8, commonSections.Length); i++)
        {
            nameFeatures[i] = sections.Any(s => s.Name?.Equals(commonSections[i], StringComparison.OrdinalIgnoreCase) == true) ? 1 : 0;
        }
        features.AddRange(nameFeatures);

        return features.ToArray();
    }

    private double[] ExtractImportFeaturesEnhanced()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var imports = _peFile.ImportedFunctions;

        var importCount = imports?.Length ?? 0;
        features.Add(Normalize(importCount, 0, 10000));

        var importsByDll = imports?.GroupBy(i => i.DLL).ToArray();
        var dllCount = importsByDll?.Length ?? 0;
        features.Add(Normalize(dllCount, 0, 100));

        if (importsByDll != null && importsByDll.Length > 0)
        {
            var importsPerDll = importsByDll.Select(g => (double)g.Count()).ToArray();
            var logImportsPerDll = importsPerDll.Select(c => Math.Log(c + 1)).ToArray();
            features.AddRange(CalculateStatistics(logImportsPerDll, 10));
        }
        else
        {
            features.AddRange(new double[10]);
        }

        var commonDlls = new[] { "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll",
                                 "ole32.dll", "oleaut32.dll", "ntdll.dll", "ws2_32.dll", "comctl32.dll" };
        var dllFeatures = new double[10];
        for (int i = 0; i < commonDlls.Length; i++)
        {
            dllFeatures[i] = importsByDll?.Any(g => g.Key?.Equals(commonDlls[i], StringComparison.OrdinalIgnoreCase) == true) == true ? 1 : 0;
        }
        features.AddRange(dllFeatures);

        features.Add(importCount > 0 ? 1 : 0);
        features.Add(Normalize(importCount, 0, 1000));
        features.Add(dllCount > 0 ? 1 : 0);
        features.Add(Normalize(dllCount, 0, 50));
        features.Add(imports?.Count(i => i.Name?.Contains("A") == true) ?? 0 / (double)Math.Max(importCount, 1));
        features.Add(imports?.Count(i => i.Name?.Contains("W") == true) ?? 0 / (double)Math.Max(importCount, 1));
        features.Add(imports?.Count(i => i.Name?.Contains("Ex") == true) ?? 0 / (double)Math.Max(importCount, 1));
        features.Add(imports?.Select(i => i.Name?.Length ?? 0).Average() ?? 0 / 100.0);
        features.Add(imports?.Count(i => i.DLL?.Contains("32") == true) ?? 0 / (double)Math.Max(dllCount, 1));
        features.Add(imports?.Count(i => i.DLL?.Contains("64") == true) ?? 0 / (double)Math.Max(dllCount, 1));

        return [.. features];
    }

    private double[] ExtractExportFeaturesEnhanced()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var exports = _peFile.ExportedFunctions;

        var exportCount = exports?.Length ?? 0;
        features.Add(Normalize(exportCount, 0, 10000));

        if (exports != null && exports.Length > 0)
        {
            var exportRvas = exports.Select(e => (double)e.Address).ToArray();
            var logExportRvas = exportRvas.Select(r => Math.Log(r + 1)).ToArray();
            features.AddRange(CalculateStatistics(logExportRvas, 10));

            var exportOrdinals = exports.Select(e => (double)e.Ordinal).ToArray();
            var logExportOrdinals = exportOrdinals.Select(o => Math.Log(o + 1)).ToArray();
            features.AddRange(CalculateStatistics(logExportOrdinals, 5));
        }
        else
        {
            features.AddRange(new double[15]);
        }

        return [.. features];
    }

    private double[] ExtractResourceFeatures()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();
        var resources = _peFile.Resources;

        if (resources == null)
        {
            return new double[16];
        }

        int resourceCount = 0;
        if (resources.Icons != null) resourceCount += resources.Icons.Length;

        features.Add(Normalize(resourceCount, 0, 1000));
        features.Add(Normalize(resources.Icons?.Length ?? 0, 0, 100));

        var iconSizes = Array.Empty<double>();
        features.AddRange(CalculateStatistics(iconSizes, 10));

        var typeFeatures = new double[4];
        typeFeatures[0] = resources.Icons != null && resources.Icons.Length > 0 ? 1 : 0;
        typeFeatures[1] = 0;
        typeFeatures[2] = 0;
        typeFeatures[3] = 0;
        features.AddRange(typeFeatures);

        return [.. features];
    }

    private double[] ExtractEntropyFeaturesEnhanced()
    {
        ArgumentNullException.ThrowIfNull(_peFile, nameof(_peFile));
        var features = new List<double>();

        var sectionEntropies = new List<double>();
        if (_peFile.ImageSectionHeaders != null)
        {
            foreach (var section in _peFile.ImageSectionHeaders)
            {
                if (section.SizeOfRawData > 0)
                {
                    var offset = (int)section.PointerToRawData;
                    var size = (int)Math.Min(section.SizeOfRawData, _fileData.Length - offset);
                    if (size > 0 && offset >= 0 && offset + size <= _fileData.Length)
                    {
                        var sectionData = new byte[size];
                        Array.Copy(_fileData, offset, sectionData, 0, size);
                        sectionEntropies.Add(CalculateEntropy(sectionData));
                    }
                }
            }
        }

        features.AddRange(CalculateStatistics(sectionEntropies.ToArray(), 16));

        var headerEntropy = CalculateEntropy(_fileData.Take(1024).ToArray());
        features.Add(headerEntropy);

        var textSection = _peFile.ImageSectionHeaders?.FirstOrDefault(s => s.Name?.Contains(".text") == true);
        if (textSection != null && textSection.SizeOfRawData > 0)
        {
            var offset = (int)textSection.PointerToRawData;
            var size = (int)Math.Min(textSection.SizeOfRawData, _fileData.Length - offset);
            if (size > 0 && offset >= 0 && offset + size <= _fileData.Length)
            {
                var textData = new byte[size];
                Array.Copy(_fileData, offset, textData, 0, size);
                features.Add(CalculateEntropy(textData));
            }
            else
            {
                features.Add(0);
            }
        }
        else
        {
            features.Add(0);
        }

        return [.. features];
    }

    private double[] ExtractByteDistributionFeatures()
    {
        var features = new List<double>();

        var byteCounts = new long[256];
        foreach (var b in _fileData)
        {
            byteCounts[b]++;
        }

        var byteFreq = byteCounts.Select(c => (double)c / _fileData.Length).ToArray();

        features.AddRange(CalculateStatistics(byteFreq, 10));

        var printableCount = byteCounts.Skip(32).Take(95).Sum();
        features.Add(Normalize(printableCount, 0, _fileData.Length));
        features.Add(Normalize(byteCounts[0], 0, _fileData.Length));
        features.Add(Normalize(byteCounts.Skip(128).Sum(), 0, _fileData.Length));
        features.Add(Normalize(byteCounts.Take(128).Sum(), 0, _fileData.Length));
        features.Add(Normalize(_fileData.Length, 0, 100_000_000));

        var buckets = new double[16];
        for (int i = 0; i < 16; i++)
        {
            var bucketSum = byteFreq.Skip(i * 16).Take(16).Sum();
            buckets[i] = bucketSum;
        }
        features.AddRange(buckets);

        var sortedFreq = byteFreq.OrderBy(f => f).ToArray();
        features.Add(byteFreq.Max());
        features.Add(byteFreq.Min());
        features.Add(byteFreq.Average());
        features.Add(byteFreq.Count(f => f > 0) / 256.0);
        
        var avg = byteFreq.Average();
        var variance = byteFreq.Average(f => (f - avg) * (f - avg));
        features.Add(variance);
        features.Add(Math.Sqrt(variance));
        features.Add(sortedFreq[127]);
        features.Add(sortedFreq[64]);
        features.Add(sortedFreq[191]);
        features.Add(sortedFreq[230]);
        features.Add(sortedFreq[243]);
        features.Add(sortedFreq[253]);
        
        var entropyOfFreq = CalculateEntropy(byteFreq.Select(f => (byte)(f * 255)).ToArray());
        features.Add(entropyOfFreq);
        
        var nonZeroFreq = byteFreq.Where(f => f > 0).ToArray();
        features.Add(nonZeroFreq.Length > 0 ? nonZeroFreq.Min() : 0);
        features.Add(nonZeroFreq.Length > 0 ? nonZeroFreq.Max() : 0);
        features.Add(nonZeroFreq.Length > 0 ? nonZeroFreq.Average() : 0);
        
        var nonZeroBytes = byteFreq.Select((f, i) => new { Freq = f, Byte = i }).Where(x => x.Freq > 0).ToList();
        features.Add(nonZeroBytes.Count > 0 ? nonZeroBytes.Average(x => (double)x.Byte) / 255.0 : 0);
        features.Add(nonZeroBytes.Count > 0 ? nonZeroBytes.Min(x => x.Byte) / 255.0 : 0);
        features.Add(nonZeroBytes.Count > 0 ? nonZeroBytes.Max(x => x.Byte) / 255.0 : 0);
        
        features.Add(Normalize(_fileData.Length > 0 ? _fileData[0] : 0, 0, 255));
        features.Add(Normalize(_fileData.Length > 1 ? _fileData[1] : 0, 0, 255));
        features.Add(Normalize(_fileData.Length > 2 ? _fileData[_fileData.Length - 1] : 0, 0, 255));
        features.Add(Normalize(_fileData.Length > 3 ? _fileData[_fileData.Length / 2] : 0, 0, 255));
        
        features.Add(byteFreq.Sum(f => f * f));
        features.Add(nonZeroBytes.Count > 0 ? nonZeroBytes.Count / 256.0 : 0);
        features.Add(sortedFreq[0]);
        features.Add(sortedFreq[255]);
        
        features.Add(byteCounts[0x4D] / (double)_fileData.Length);
        features.Add(byteCounts[0x5A] / (double)_fileData.Length);
        features.Add(byteCounts[0x50] / (double)_fileData.Length);
        features.Add(byteCounts[0x45] / (double)_fileData.Length);
        features.Add(Normalize(_fileData.Length > 4 ? _fileData[4] : 0, 0, 255));
        features.Add(Normalize(_fileData.Length > 5 ? _fileData[5] : 0, 0, 255));
        features.Add(Normalize(_fileData.Length > 6 ? _fileData[6] : 0, 0, 255));

        return features.ToArray();
    }

    private double[] CalculateStatistics(double[] values, int outputCount)
    {
        var result = new double[outputCount];

        if (values == null || values.Length == 0)
        {
            return result;
        }

        var validValues = values.Where(v => !double.IsNaN(v) && !double.IsInfinity(v)).ToArray();

        if (validValues.Length == 0)
        {
            return result;
        }

        var mean = validValues.Average();
        var min = validValues.Min();
        var max = validValues.Max();
        var variance = validValues.Length > 1 ? validValues.Average(v => Math.Pow(v - mean, 2)) : 0;
        var stdDev = Math.Sqrt(variance);
        var median = CalculateMedian(validValues);
        var range = max - min;

        result[0] = Normalize(mean, -1000000, 1000000);
        result[1] = Normalize(min, -1000000, 1000000);
        result[2] = Normalize(max, -1000000, 1000000);
        result[3] = Normalize(variance, 0, 1e12);
        result[4] = Normalize(stdDev, 0, 1e6);
        result[5] = Normalize(median, -1000000, 1000000);
        result[6] = Normalize(range, 0, 2e6);
        result[7] = Normalize(validValues.Length, 0, 10000);

        if (outputCount > 8)
        {
            var sorted = validValues.OrderBy(v => v).ToArray();
            for (int i = 8; i < outputCount && i - 8 < sorted.Length; i++)
            {
                var index = (int)((i - 8) * (sorted.Length - 1) / (outputCount - 8));
                result[i] = Normalize(sorted[index], -1000000, 1000000);
            }
        }

        return result;
    }

    private double CalculateMedian(double[] values)
    {
        var sorted = values.OrderBy(v => v).ToArray();
        var mid = sorted.Length / 2;
        return sorted.Length % 2 == 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
    }

    private double CalculateEntropy(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return 0;
        }

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

    private double Normalize(double value, double min, double max)
    {
        if (max == min)
        {
            return 0;
        }

        var normalized = (value - min) / (max - min);
        return Math.Clamp(normalized, 0, 1);
    }
}
