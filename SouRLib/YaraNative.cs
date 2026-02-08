using System;
using System.Runtime.InteropServices;

namespace SouRLib;

public static class YaraNative
{
    private const string YaraDll = "libyara64.dll";

    #region 错误码定义

    public const int ERROR_SUCCESS = 0;
    public const int ERROR_INSUFFICIENT_MEMORY = 1;
    public const int ERROR_COULD_NOT_ATTACH_TO_PROCESS = 2;
    public const int ERROR_COULD_NOT_OPEN_FILE = 3;
    public const int ERROR_COULD_NOT_MAP_FILE = 4;
    public const int ERROR_INVALID_FILE = 5;
    public const int ERROR_CORRUPT_FILE = 6;
    public const int ERROR_UNSUPPORTED_FILE_VERSION = 7;
    public const int ERROR_INVALID_REGULAR_EXPRESSION = 8;
    public const int ERROR_INVALID_HEX_STRING = 9;
    public const int ERROR_SYNTAX_ERROR = 10;
    public const int ERROR_LOOP_NESTING_LIMIT_EXCEEDED = 11;
    public const int ERROR_DUPLICATED_LOOP_IDENTIFIER = 12;
    public const int ERROR_DUPLICATED_IDENTIFIER = 13;
    public const int ERROR_DUPLICATED_TAG_IDENTIFIER = 14;
    public const int ERROR_DUPLICATED_META_IDENTIFIER = 15;
    public const int ERROR_DUPLICATED_STRING_IDENTIFIER = 16;
    public const int ERROR_UNREFERENCED_STRING = 17;
    public const int ERROR_UNDEFINED_STRING = 18;
    public const int ERROR_UNDEFINED_IDENTIFIER = 19;
    public const int ERROR_MISPLACED_ANONYMOUS_STRING = 20;
    public const int ERROR_INCLUDES_CIRCULAR_REFERENCE = 21;
    public const int ERROR_INCLUDE_DEPTH_EXCEEDED = 22;
    public const int ERROR_WRONG_TYPE = 23;
    public const int ERROR_EXEC_STACK_OVERFLOW = 24;
    public const int ERROR_SCAN_TIMEOUT = 25;
    public const int ERROR_TOO_MANY_SCAN_THREADS = 26;
    public const int ERROR_CALLBACK_ERROR = 27;
    public const int ERROR_INVALID_ARGUMENT = 28;
    public const int ERROR_TOO_MANY_MATCHES = 29;
    public const int ERROR_INTERNAL_FATAL_ERROR = 30;
    public const int ERROR_NESTED_FOR_OF_LOOP = 31;
    public const int ERROR_INVALID_FIELD_NAME = 32;
    public const int ERROR_UNKNOWN_MODULE = 33;
    public const int ERROR_NOT_A_STRUCTURE = 34;
    public const int ERROR_NOT_AN_ARRAY = 35;
    public const int ERROR_NOT_A_FUNCTION = 36;
    public const int ERROR_INVALID_FORMAT = 37;
    public const int ERROR_TOO_MANY_ARGUMENTS = 38;
    public const int ERROR_WRONG_ARGUMENTS = 39;
    public const int ERROR_WRONG_RETURN_TYPE = 40;

    #endregion

    #region 回调委托

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int YR_CALLBACK_FUNC(
        IntPtr context,
        int message,
        IntPtr rule,
        IntPtr data
    );

    public const int CALLBACK_MSG_RULE_MATCHING = 1;
    public const int CALLBACK_MSG_RULE_NOT_MATCHING = 2;
    public const int CALLBACK_MSG_TOO_MANY_MATCHES = 3;
    public const int CALLBACK_MSG_CONSOLE_LOG = 4;

    public const int CALLBACK_CONTINUE = 0;
    public const int CALLBACK_ABORT = 1;
    public const int CALLBACK_ERROR = 2;

    #endregion

    #region 初始化与销毁函数

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_initialize();

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_finalize();

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void yr_finalize_thread();

    #endregion

    #region 编译器相关函数

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_compiler_create(out IntPtr compiler);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void yr_compiler_destroy(IntPtr compiler);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_compiler_add_file(
        IntPtr compiler,
        IntPtr file,
        IntPtr namespace_,
        string file_path
    );

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_compiler_add_string(
        IntPtr compiler,
        string rules_string,
        IntPtr namespace_
    );

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int yr_compiler_add_fd(
        IntPtr compiler,
        IntPtr fd,
        IntPtr namespace_,
        string file_path
    );

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_compiler_get_rules(IntPtr compiler, out IntPtr rules);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void yr_compiler_set_callback(
        IntPtr compiler,
        IntPtr callback,
        IntPtr user_data
    );

    #endregion

    #region 规则相关函数

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_rules_create(out IntPtr rules);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern void yr_rules_destroy(IntPtr rules);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_rules_load(string filename, out IntPtr rules);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_rules_save(IntPtr rules, string filename);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_rules_scan_file(
        IntPtr rules,
        string filename,
        int flags,
        YR_CALLBACK_FUNC callback,
        IntPtr user_data,
        int timeout
    );

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_rules_scan_mem(
        IntPtr rules,
        byte[] buffer,
        UIntPtr length,
        int flags,
        YR_CALLBACK_FUNC callback,
        IntPtr user_data,
        int timeout
    );

    #endregion

    #region 规则迭代相关

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr yr_rule_tags(IntPtr rule);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr yr_rule_metas(IntPtr rule);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr yr_rule_strings(IntPtr rule);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr yr_rule_namespace(IntPtr rule);

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_rule_get_string(
        IntPtr rule,
        int string_idx,
        out IntPtr string_ptr
    );

    #endregion

    #region 辅助函数

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr yr_get_error_message();

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int yr_get_last_error();

    [DllImport(YaraDll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr yr_rule_identifier(IntPtr rule);

    #endregion

    #region 扫描标志

    public const int SCAN_FLAGS_FAST_MODE = 1;
    public const int SCAN_FLAGS_PROCESS_MEMORY = 2;
    public const int SCAN_FLAGS_NO_TRYCATCH = 4;
    public const int SCAN_FLAGS_REPORT_RULES_MATCHING = 8;
    public const int SCAN_FLAGS_REPORT_RULES_NOT_MATCHING = 16;

    #endregion
}
