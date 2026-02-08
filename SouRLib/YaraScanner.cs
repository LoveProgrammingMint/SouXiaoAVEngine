using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SouRLib;

public class YaraScanner : IDisposable
{
    private IntPtr _compiler = IntPtr.Zero;
    private IntPtr _rules = IntPtr.Zero;
    private bool _initialized = false;
    private readonly List<YaraMatch> _matches = new();
    private YaraNative.YR_CALLBACK_FUNC? _callback;

    public bool IsInitialized => _initialized;
    public IntPtr RulesHandle => _rules;

    public class YaraMatch
    {
        public string RuleName { get; set; } = string.Empty;
        public string Namespace { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = [];
        public Dictionary<string, object> Metadata { get; set; } = [];
    }

    public class YaraException(int errorCode, string message) : Exception(message)
    {
        public int ErrorCode { get; } = errorCode;
    }

    public void Initialize()
    {
        if (_initialized)
            return;

        int result = YaraNative.yr_initialize();
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"YARA Init Failed, CODE: {result}");
        }

        _initialized = true;
    }

    public void AddRulesFromFile(string filePath)
    {
        EnsureInitialized();

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File NotFound: {filePath}");
        }

        if (_compiler == IntPtr.Zero)
        {
            int result = YaraNative.yr_compiler_create(out _compiler);
            if (result != YaraNative.ERROR_SUCCESS)
            {
                throw new YaraException(result, $"Create Compiler, CODE: {result}");
            }
        }

        string ruleContent = File.ReadAllText(filePath, Encoding.UTF8);

        int addResult = YaraNative.yr_compiler_add_string(_compiler, ruleContent, IntPtr.Zero);
        if (addResult != 0)
        {
            throw new YaraException(addResult, $"Add Rule Failed, Failed Number: {addResult}");
        }

    }

    public void AddRulesFromString(string rules)
    {
        EnsureInitialized();

        if (_compiler == IntPtr.Zero)
        {
            int result = YaraNative.yr_compiler_create(out _compiler);
            if (result != YaraNative.ERROR_SUCCESS)
            {
                throw new YaraException(result, $"Create Compiler, CODE: {result}");
            }
        }

        int addResult = YaraNative.yr_compiler_add_string(_compiler, rules, IntPtr.Zero);
        if (addResult != 0)
        {
            throw new YaraException(addResult, $"Add Rule Failed, Failed Number: {addResult}");
        }
    }

    public void CompileRules()
    {
        EnsureInitialized();

        if (_compiler == IntPtr.Zero)
        {
            throw new InvalidOperationException("No compilable rules available, Please add the rules first");
        }

        if (_rules != IntPtr.Zero)
        {
            YaraNative.yr_rules_destroy(_rules);
            _rules = IntPtr.Zero;
        }

        int result = YaraNative.yr_compiler_get_rules(_compiler, out _rules);
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"Compilation rule failed, CODE: {result}");
        }

        YaraNative.yr_compiler_destroy(_compiler);
        _compiler = IntPtr.Zero;

    }

    public List<YaraMatch> ScanFile(string filePath, int timeout = 0)
    {
        EnsureRulesCompiled();

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Scan File NotFound: {filePath}");
        }

        _matches.Clear();
        _callback = new YaraNative.YR_CALLBACK_FUNC(OnRuleMatch);

        int result = YaraNative.yr_rules_scan_file(
            _rules,
            filePath,
            YaraNative.SCAN_FLAGS_REPORT_RULES_MATCHING,
            _callback,
            IntPtr.Zero,
            timeout
        );

        if (result != YaraNative.ERROR_SUCCESS && result != YaraNative.CALLBACK_ABORT)
        {
            throw new YaraException(result, $"Scan File Failed, CODE: {result}");
        }

        return _matches;
    }

    public List<YaraMatch> ScanMemory(byte[] data, int timeout = 0)
    {
        EnsureRulesCompiled();

        if (data == null || data.Length == 0)
        {
            throw new ArgumentException("Scan data cannot be empty");
        }

        _matches.Clear();
        _callback = new YaraNative.YR_CALLBACK_FUNC(OnRuleMatch);

        int result = YaraNative.yr_rules_scan_mem(
            _rules,
            data,
            (UIntPtr)data.Length,
            YaraNative.SCAN_FLAGS_REPORT_RULES_MATCHING,
            _callback,
            IntPtr.Zero,
            timeout
        );

        if (result != YaraNative.ERROR_SUCCESS && result != YaraNative.CALLBACK_ABORT)
        {
            throw new YaraException(result, $"Failed to scan memory, CODE: {result}");
        }

        return _matches;
    }

    public void LoadCompiledRules(string filePath)
    {
        EnsureInitialized();

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"The compiled rule file does not exist: {filePath}");
        }

        if (_rules != IntPtr.Zero)
        {
            YaraNative.yr_rules_destroy(_rules);
            _rules = IntPtr.Zero;
        }

        int result = YaraNative.yr_rules_load(filePath, out _rules);
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"Failed to load compilation rules, CODE: {result}");
        }
    }

    public void SaveCompiledRules(string filePath)
    {
        EnsureRulesCompiled();

        int result = YaraNative.yr_rules_save(_rules, filePath);
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"Failed to save compilation rules, CODE: {result}");
        }
    }

    private int OnRuleMatch(IntPtr context, int message, IntPtr rule, IntPtr data)
    {
        if (message == YaraNative.CALLBACK_MSG_RULE_MATCHING && rule != IntPtr.Zero)
        {
            try
            {
                var match = new YaraMatch();

                try
                {
                    IntPtr identifierPtr = YaraNative.yr_rule_identifier(rule);
                    if (identifierPtr != IntPtr.Zero)
                    {
                        match.RuleName = Marshal.PtrToStringAnsi(identifierPtr) ?? "unknown";
                    }
                }
                catch (EntryPointNotFoundException)
                {
                    match.RuleName = $"rule_{_matches.Count + 1}";
                }

                try
                {
                    IntPtr namespacePtr = YaraNative.yr_rule_namespace(rule);
                    if (namespacePtr != IntPtr.Zero)
                    {
                        match.Namespace = Marshal.PtrToStringAnsi(namespacePtr) ?? "default";
                    }
                }
                catch (EntryPointNotFoundException)
                {
                    match.Namespace = "default";
                }

                _matches.Add(match);
            }
            catch (Exception)
            {
            }
        }

        return YaraNative.CALLBACK_CONTINUE;
    }

    private void EnsureInitialized()
    {
        if (!_initialized)
        {
            throw new InvalidOperationException("YARA is not initialized, please call Initialize () first");
        }
    }

    private void EnsureRulesCompiled()
    {
        EnsureInitialized();

        if (_rules == IntPtr.Zero)
        {
            throw new InvalidOperationException("There are no compiled rules, please add and compile the rules first");
        }
    }

    public void Destroy()
    {
        if (_rules != IntPtr.Zero)
        {
            YaraNative.yr_rules_destroy(_rules);
            _rules = IntPtr.Zero;
        }

        if (_compiler != IntPtr.Zero)
        {
            YaraNative.yr_compiler_destroy(_compiler);
            _compiler = IntPtr.Zero;
        }

        if (_initialized)
        {
            try
            {
                YaraNative.yr_finalize_thread();
            }
            catch (EntryPointNotFoundException)
            {
                // 忽略
            }
            _ = YaraNative.yr_finalize();
            _initialized = false;
        }

        _callback = null;
    }

    public void Dispose()
    {
        Destroy();
        GC.SuppressFinalize(this);
    }

    ~YaraScanner()
    {
        Destroy();
    }
}
