using LiuLiAVHeuristic;
using PublicPart;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace MuChenScaffold;

internal class FunctionsLoop
{
    private bool Is_Installed = false;
    private const int MaxConnections = 20;
    private static readonly SemaphoreSlim _semaphore = new(MaxConnections, MaxConnections);
    private bool In_Loop = true;
    private bool _isRunning = true;
    private bool Is_Active = false;
    private LiuLiEntry LiuLi = new();
    private String Name = "Admin";

    public void Start()
    {
        Console.WriteLine("Starting...");
        Console.WriteLine("Not installed, starting installation...");
        Console.WriteLine("Please Input Install-Packet Path:");
        String Path = Console.ReadLine() ?? ".\\packet.muchen";
        ZipFile.ExtractToDirectory(Path.Replace("\"", "").Replace("'", ""), ".\\", overwriteFiles: true);
        Name = File.ReadAllText(".\\UserData.packetdata");
        File.WriteAllText("Settings.txt", "True");
        Is_Installed = true;
        Console.WriteLine("Installation completed.");

    }

    public void Loop()
    {   
        while (In_Loop)
        {
            if (File.Exists(".\\UserData.packetdata")) Name = File.ReadAllText(".\\UserData.packetdata");
            Console.Write($"\nMuChenScaffold $ {Name}>");
            String? Command = Console.ReadLine();
            RunCommand(Command);
        }
    }

    public void RunCommand(String? Command)
    {
        if (Command == null || Command == String.Empty) return;
        String[] CommandList = Command.Split(" ");
        switch (CommandList[0].ToLower())
        {
            case "active":
                Active();
                break;

            case "run":
                Run(CommandList);
                break;

            case "install":
                Start();
                break;

            case "-version":
                Console.WriteLine($"Vision: MuChen v1.0.3 | LiuLi v{LiuLi.VERSION}");
                break;

            case "-v":
                Console.WriteLine($"Vision: MuChen v1.0.3 | LiuLi v{LiuLi.VERSION}");
                break;

            case "exit":
                In_Loop = false;
                break;

            default:
                break;
        }
    }

    public void Active()
    {
        if (!Is_Installed) { Console.WriteLine("No Install!"); return; }
        LiuLi.Initialize(".\\LiuLi.onnx");
        Console.WriteLine("Active Success !");
        Is_Active = true;
    }

    public void Run(String[] CommandList)
    {
        int Post = Convert.ToInt32(CommandList[1]);
        TcpListener listener = new(IPAddress.Any, Post);
        try
        {
            _isRunning = true;
            listener.Start();
            Console.WriteLine($"[MuChen - Run] Listening: 1234");
            Console.WriteLine($"[MuChen - Run - Setting] Max Clients: {MaxConnections}");
            Console.WriteLine("Tap Ctrl+C to Stop...\n");

            while (_isRunning)
            {

                _semaphore.Wait();

                listener.BeginAcceptTcpClient(OnClientConnected, listener);

                Thread.Sleep(100);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Failed] Server Failed: {ex.Message}");
        }
        finally
        {
            listener.Stop();
            Console.WriteLine("[SERVER STOPED]");
            _isRunning = false;
        }
    }

    private void OnClientConnected(IAsyncResult ar)
    {
        TcpListener? listener = (TcpListener?)ar.AsyncState;
        TcpClient? client = null;

        try
        {
            ArgumentNullException.ThrowIfNull(listener);
            client = listener.EndAcceptTcpClient(ar);

            IPEndPoint? remoteEndPoint = (IPEndPoint?)client.Client.RemoteEndPoint;
            Console.WriteLine($"[Link] Client Link in: {remoteEndPoint} | Active Clients : {MaxConnections - _semaphore.CurrentCount}");

            Thread clientThread = new(new ParameterizedThreadStart(HandleClient))
            {
                IsBackground = true
            };
            clientThread.Start(client);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Failed] Link Failed: {ex.Message}");
            _semaphore.Release();
        }

        if (_isRunning)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(listener);
                listener.BeginAcceptTcpClient(OnClientConnected, listener);
            }
            catch { }
        }
    }

    private void HandleClient(object? obj)
    {
        TcpClient? client = (TcpClient?)obj;
        IPEndPoint? remoteEndPoint = (IPEndPoint?)client?.Client.RemoteEndPoint;

        try
        {
            ArgumentNullException.ThrowIfNull(client);
            using NetworkStream stream = client.GetStream();
            byte[] buffer = new byte[4096];

            while (client.Connected && _isRunning)
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);

                if (bytesRead == 0)
                {
                    Console.WriteLine($"[Link] Client Active Disconnect: {remoteEndPoint}");
                    break;
                }

                string received = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                Console.WriteLine($"[Receive] {remoteEndPoint}: {received.Trim()}");

                string response = Scan(received);

                byte[] responseBytes = Encoding.UTF8.GetBytes(response);
                stream.Write(responseBytes, 0, responseBytes.Length);
                stream.Flush();

                Console.WriteLine($"[Response] {remoteEndPoint}: {response.Trim()}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Failed] Processing Clients {remoteEndPoint} Thorw Exception: {ex.Message}");
        }
        finally
        {

            client?.Close();
            _semaphore.Release();

            Console.WriteLine($"[Clear] Link Disconnect: {remoteEndPoint} | Other Unactive Clients: {_semaphore.CurrentCount}");
        }
    }

    public String Scan(String FilePath)
    {
        if (!File.Exists(FilePath)) return "FileNotFound!";
        if (!Is_Active) return "No Active,Please first use \"Active\" Command to active Engine!";
        var Result = LiuLi.ScanforMuChen(PeNet.PeFile.IsPeFile(FilePath),FilePath);
        return Result.Item1 switch
        {
            [EngineResult.Safe] => $"SAFE;{Result.Item2}",
            [EngineResult.Malicious] => $"UNSAFE;{Result.Item2}",
            _ => $"UNSUPPORT;{Result.Item2}",
        };
    }

}

