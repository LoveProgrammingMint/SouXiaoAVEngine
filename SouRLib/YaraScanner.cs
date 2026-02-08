using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ConsoleApp;

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
        public List<string> Tags { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    public class YaraException : Exception
    {
        public int ErrorCode { get; }

        public YaraException(int errorCode, string message) : base(message)
        {
            ErrorCode = errorCode;
        }
    }

    public void Initialize()
    {
        if (_initialized)
            return;

        int result = YaraNative.yr_initialize();
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"YARA 初始化失败，错误码: {result}");
        }

        _initialized = true;
        Console.WriteLine("[YARA] 初始化成功");
    }

    public void AddRulesFromFile(string filePath)
    {
        EnsureInitialized();

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"规则文件不存在: {filePath}");
        }

        if (_compiler == IntPtr.Zero)
        {
            int result = YaraNative.yr_compiler_create(out _compiler);
            if (result != YaraNative.ERROR_SUCCESS)
            {
                throw new YaraException(result, $"创建编译器失败，错误码: {result}");
            }
        }

        // 读取规则文件内容
        string ruleContent = File.ReadAllText(filePath, Encoding.UTF8);

        // 使用 yr_compiler_add_string 添加规则
        int addResult = YaraNative.yr_compiler_add_string(_compiler, ruleContent, IntPtr.Zero);
        if (addResult != 0)
        {
            throw new YaraException(addResult, $"添加规则失败，错误数: {addResult}");
        }

        Console.WriteLine($"[YARA] 成功添加规则文件: {filePath}");
    }

    public void AddRulesFromString(string rules)
    {
        EnsureInitialized();

        if (_compiler == IntPtr.Zero)
        {
            int result = YaraNative.yr_compiler_create(out _compiler);
            if (result != YaraNative.ERROR_SUCCESS)
            {
                throw new YaraException(result, $"创建编译器失败，错误码: {result}");
            }
        }

        int addResult = YaraNative.yr_compiler_add_string(_compiler, rules, IntPtr.Zero);
        if (addResult != 0)
        {
            throw new YaraException(addResult, $"添加规则失败，错误数: {addResult}");
        }

        Console.WriteLine("[YARA] 成功添加规则字符串");
    }

    public void CompileRules()
    {
        EnsureInitialized();

        if (_compiler == IntPtr.Zero)
        {
            throw new InvalidOperationException("没有可编译的规则，请先添加规则");
        }

        // 销毁旧规则
        if (_rules != IntPtr.Zero)
        {
            YaraNative.yr_rules_destroy(_rules);
            _rules = IntPtr.Zero;
        }

        int result = YaraNative.yr_compiler_get_rules(_compiler, out _rules);
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"编译规则失败，错误码: {result}");
        }

        // 编译完成后可以销毁编译器
        YaraNative.yr_compiler_destroy(_compiler);
        _compiler = IntPtr.Zero;

        Console.WriteLine("[YARA] 规则编译成功");
    }

    public List<YaraMatch> ScanFile(string filePath, int timeout = 0)
    {
        EnsureRulesCompiled();

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"扫描文件不存在: {filePath}");
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
            throw new YaraException(result, $"扫描文件失败，错误码: {result}");
        }

        Console.WriteLine($"[YARA] 扫描完成，发现 {_matches.Count} 个匹配");
        return new List<YaraMatch>(_matches);
    }

    public List<YaraMatch> ScanMemory(byte[] data, int timeout = 0)
    {
        EnsureRulesCompiled();

        if (data == null || data.Length == 0)
        {
            throw new ArgumentException("扫描数据不能为空");
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
            throw new YaraException(result, $"扫描内存失败，错误码: {result}");
        }

        Console.WriteLine($"[YARA] 内存扫描完成，发现 {_matches.Count} 个匹配");
        return new List<YaraMatch>(_matches);
    }

    public void LoadCompiledRules(string filePath)
    {
        EnsureInitialized();

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"编译后的规则文件不存在: {filePath}");
        }

        // 销毁旧规则
        if (_rules != IntPtr.Zero)
        {
            YaraNative.yr_rules_destroy(_rules);
            _rules = IntPtr.Zero;
        }

        int result = YaraNative.yr_rules_load(filePath, out _rules);
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"加载编译规则失败，错误码: {result}");
        }

        Console.WriteLine($"[YARA] 成功加载编译后的规则: {filePath}");
    }

    public void SaveCompiledRules(string filePath)
    {
        EnsureRulesCompiled();

        int result = YaraNative.yr_rules_save(_rules, filePath);
        if (result != YaraNative.ERROR_SUCCESS)
        {
            throw new YaraException(result, $"保存编译规则失败，错误码: {result}");
        }

        Console.WriteLine($"[YARA] 成功保存编译后的规则到: {filePath}");
    }

    private int OnRuleMatch(IntPtr context, int message, IntPtr rule, IntPtr data)
    {
        if (message == YaraNative.CALLBACK_MSG_RULE_MATCHING && rule != IntPtr.Zero)
        {
            try
            {
                var match = new YaraMatch();

                // 尝试获取规则名称
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

                // 尝试获取命名空间
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
            catch (Exception ex)
            {
                Console.WriteLine($"[YARA] 处理匹配结果时出错: {ex.Message}");
            }
        }

        return YaraNative.CALLBACK_CONTINUE;
    }

    private void EnsureInitialized()
    {
        if (!_initialized)
        {
            throw new InvalidOperationException("YARA 未初始化，请先调用 Initialize()");
        }
    }

    private void EnsureRulesCompiled()
    {
        EnsureInitialized();

        if (_rules == IntPtr.Zero)
        {
            throw new InvalidOperationException("没有编译的规则，请先添加并编译规则");
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
            // yr_finalize_thread 在某些版本的 YARA 中可能不存在
            try
            {
                YaraNative.yr_finalize_thread();
            }
            catch (EntryPointNotFoundException)
            {
                // 忽略此错误
            }
            YaraNative.yr_finalize();
            _initialized = false;
        }

        _callback = null;
        Console.WriteLine("[YARA] 已销毁");
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
