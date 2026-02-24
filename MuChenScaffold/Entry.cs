using System.Runtime.InteropServices;

namespace MuChenScaffold
{
    internal class Entry
    {
        [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
        [DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out int m);
        [DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, int m);
        const int STD_OUTPUT = -11, VT_MODE = 0x0004;

        static void Main()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var h = GetStdHandle(STD_OUTPUT);
                GetConsoleMode(h, out int m);
                SetConsoleMode(h, m | VT_MODE);
            }

            var start = HexToRgb("5EFCE8");
            var end = HexToRgb("736EFE");

            string text = "Welcome to use MuChen Scaffold!";

            for (int i = 0; i < text.Length; i++)
            {
                double t = (double)i / Math.Max(1, text.Length - 1);
                var c = Lerp(start, end, t);
                Console.Write($"\x1b[38;2;{c.r};{c.g};{c.b}m{text[i]}");
            }
            Console.WriteLine("\x1b[0m");
            Console.WriteLine("  __  __        ____ _                  ____             __  __       _     _ \r\n |  \\/  |_   _ / ___| |__   ___ _ __   / ___|  ___ __ _ / _|/ _| ___ | | __| |\r\n | |\\/| | | | | |   | '_ \\ / _ \\ '_ \\  \\___ \\ / __/ _` | |_| |_ / _ \\| |/ _` |\r\n | |  | | |_| | |___| | | |  __/ | | |  ___) | (_| (_| |  _|  _| (_) | | (_| |\r\n |_|  |_|\\__,_|\\____|_| |_|\\___|_| |_| |____/ \\___\\__,_|_| |_|  \\___/|_|\\__,_|\r\n                                                                              ");
            var loop = new FunctionsLoop();
            loop.Loop();
        }

        static (byte r, byte g, byte b) HexToRgb(string hex)
        {
            hex = hex.TrimStart('#');
            return (
                Convert.ToByte(hex.Substring(0, 2), 16),
                Convert.ToByte(hex.Substring(2, 2), 16),
                Convert.ToByte(hex.Substring(4, 2), 16)
            );
        }

        static (byte r, byte g, byte b) Lerp((byte r, byte g, byte b) a, (byte r, byte g, byte b) b, double t)
        {
            return (
                (byte)(a.r + (b.r - a.r) * t),
                (byte)(a.g + (b.g - a.g) * t),
                (byte)(a.b + (b.b - a.b) * t)
            );
        }
    }
}
