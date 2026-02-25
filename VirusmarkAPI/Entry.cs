using Newtonsoft.Json;
using PublicPart;
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VirusmarkAPI;

public class VirusScanner : IEngineEntry
{
    private string? url;
    private HttpClient? client;

    public string VERSION { get; set; } = "1.1.2";

    public void Dispose()
    {
        client?.Dispose();
        GC.SuppressFinalize(this);
    }

    public bool Initialize(string Address)
    {
        client = new HttpClient();
        url = Address;
        return true;
    }

    public List<EngineResult> Scan(bool IsPE, string? FilePath)
    {
        String SHA256Hash = ComputeFileSha256Async(FilePath ?? "").GetAwaiter().GetResult();
        string response = ScanWithHashesAsync("APIKEY", SHA256Hash).GetAwaiter().GetResult();
        Console.WriteLine(response);
        return new List<EngineResult> { EngineResult.UnSupport };
    }

    public static async Task<string> ComputeFileSha256Async(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                return "Failed";
            }

            using FileStream stream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
            using SHA256 sha256 = SHA256.Create();
            long totalBytes = stream.Length;
            long processedBytes = 0;
            byte[] buffer = new byte[81920];
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer)) > 0)
            {
                processedBytes += bytesRead;

                if (bytesRead == buffer.Length)
                {
                    sha256.TransformBlock(buffer, 0, bytesRead, null, 0);
                }
                else
                {
                    sha256.TransformFinalBlock(buffer, 0, bytesRead);
                }
            }

            byte[]? hashBytes = sha256.Hash;
            StringBuilder sb = new();
            if (hashBytes != null)
            {
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
            }
            return sb.ToString();
        }
        catch (Exception)
        {
            return "Failed";
        }
    }

    public async Task<string> ScanWithHashesAsync(string token, string sha256Value)
    {
        try
        { 
            ArgumentNullException.ThrowIfNull(client, nameof(client));
            ArgumentNullException.ThrowIfNull(url, nameof(url));
            var requestData = new
            {
                token,
                hashes = new[] { sha256Value }
            };

            string jsonContent = JsonConvert.SerializeObject(requestData);
            var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync(url, content);
            string responseText = await response.Content.ReadAsStringAsync();

            return responseText;
        }
        catch (Exception ex)
        {
            return "Failed to scan: " + ex.Message;
        }
    }

}