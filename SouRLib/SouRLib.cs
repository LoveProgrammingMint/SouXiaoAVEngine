using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ConsoleApp;

internal class SouRLib : IDisposable
{
    private YaraScanner? _scanner;
    private string? _rulesDirectory;
    private string? _compiledRulesDirectory;
    private bool _initialized = false;
    private readonly List<string> _loadedRuleFiles = new();

    public bool IsInitialized => _initialized;

    public IReadOnlyList<string> LoadedRuleFiles => _loadedRuleFiles.AsReadOnly();

    public bool Initialize(string rulesDirectory)
    {
        if (_initialized)
        {
            return true;
        }

        try
        {

            if (!Directory.Exists(rulesDirectory))
            {
                return false;
            }

            _rulesDirectory = rulesDirectory;
            _compiledRulesDirectory = Path.Combine(rulesDirectory, "YarC");

            _scanner = new YaraScanner();
            _scanner.Initialize();

            _initialized = true;
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
    public int ProcessRules()
    {
        EnsureInitialized();

        if (string.IsNullOrEmpty(_rulesDirectory) || string.IsNullOrEmpty(_compiledRulesDirectory))
        {

            return 0;
        }

        try
        {

            var yarFiles = Directory.GetFiles(_rulesDirectory, "*.yar", SearchOption.TopDirectoryOnly);

            if (yarFiles.Length == 0)
            {
                return 0;
            }

            if (!Directory.Exists(_compiledRulesDirectory))
            {
                Directory.CreateDirectory(_compiledRulesDirectory);
            }

            int processedCount = 0;

            foreach (var yarFile in yarFiles)
            {
                try
                {
                    string fileName = Path.GetFileNameWithoutExtension(yarFile);
                    string yarcFile = Path.Combine(_compiledRulesDirectory, fileName + ".yarc");

                    bool needCompile = true;
                    if (File.Exists(yarcFile))
                    {
                        var yarTime = File.GetLastWriteTime(yarFile);
                        var yarcTime = File.GetLastWriteTime(yarcFile);
                        if (yarcTime > yarTime)
                        {
                            needCompile = false;
                        }
                    }

                    if (needCompile)
                    {
                        using var compiler = new YaraScanner();
                        compiler.Initialize();
                        compiler.AddRulesFromFile(yarFile);
                        compiler.CompileRules();
                        compiler.SaveCompiledRules(yarcFile);

                        processedCount++;
                    }
                }
                catch (Exception)
                {
                }
            }
            return processedCount;
        }
        catch (Exception)
        {
            return 0;
        }
    }

    public int LoadCompiledRules()
    {
        EnsureInitialized();

        if (string.IsNullOrEmpty(_compiledRulesDirectory))
        {
            return 0;
        }

        try
        {
            ProcessRules();

            var yarcFiles = Directory.GetFiles(_compiledRulesDirectory, "*.yarc", SearchOption.TopDirectoryOnly);

            if (yarcFiles.Length == 0)
            {
                return 0;
            }

            _loadedRuleFiles.Clear();

            if (_scanner?.RulesHandle != IntPtr.Zero)
            {
                _scanner?.Destroy();
                _scanner = new YaraScanner();
                _scanner.Initialize();
            }

            int loadedCount = 0;
            var combinedRules = new StringBuilder();

            foreach (var yarcFile in yarcFiles)
            {
                try
                {
                    string fileName = Path.GetFileName(yarcFile);

                    _scanner?.LoadCompiledRules(yarcFile);
                    _loadedRuleFiles.Add(yarcFile);
                    loadedCount++;
                }
                catch (Exception)
                {
                }
            }

            return loadedCount;
        }
        catch (Exception)
        {
            return 0;
        }
    }

    public List<YaraScanner.YaraMatch> ScanFile(string filePath)
    {
        EnsureInitialized();

        if (_scanner == null)
        {
            throw new InvalidOperationException("Not Init");
        }

        if (!File.Exists(filePath))
        {
            return [];
        }

        try
        {
            var matches = _scanner.ScanFile(filePath);
            return matches;
        }
        catch (Exception)
        {
            return [];
        }
    }

    public List<YaraScanner.YaraMatch> ScanMemory(byte[] data)
    {
        EnsureInitialized();

        if (_scanner == null)
        {
            throw new InvalidOperationException("Not Init");
        }

        if (data == null || data.Length == 0)
        {
            return [];
        }

        try
        {
            var matches = _scanner.ScanMemory(data);
            return matches;
        }
        catch (Exception)
        {
            return [];
        }
    }

    public Dictionary<string, List<YaraScanner.YaraMatch>> ScanDirectory(string directory, string searchPattern = "*.*")
    {
        var results = new Dictionary<string, List<YaraScanner.YaraMatch>>();

        if (!Directory.Exists(directory))
        {
            return results;
        }

        try
        {
            var files = Directory.GetFiles(directory, searchPattern, SearchOption.TopDirectoryOnly);

            int scannedCount = 0;
            int matchCount = 0;

            foreach (var file in files)
            {
                var matches = ScanFile(file);
                if (matches.Count > 0)
                {
                    results[file] = matches;
                    matchCount += matches.Count;
                }
                scannedCount++;
            }

            return results;
        }
        catch (Exception)
        {
            return results;
        }
    }

    public void Cleanup()
    {
        try
        {
            _scanner?.Destroy();
            _scanner = null;
            _loadedRuleFiles.Clear();
            _initialized = false;
        }
        catch (Exception)
        {

        }
    }

    public class Status
    {
        public bool Initialized { get; set; }
        public string? RulesDirectory { get; set; }
        public string? CompiledRulesDirectory { get; set; }
        public List<string> LoadedRuleFiles { get; set; } = [];

    }

    public Status GetStatus()
    {
        return new Status()
        {
            Initialized = _initialized,
            RulesDirectory = _rulesDirectory,
            CompiledRulesDirectory = _compiledRulesDirectory,
            LoadedRuleFiles = _loadedRuleFiles
        };
    }

    private void EnsureInitialized()
    {
        if (!_initialized)
        {
            throw new InvalidOperationException("Not Init. First Use Initialize()");
        }
    }

    public void Dispose()
    {
        Cleanup();
        GC.SuppressFinalize(this);
    }

    ~SouRLib()
    {
        Cleanup();
    }
}
