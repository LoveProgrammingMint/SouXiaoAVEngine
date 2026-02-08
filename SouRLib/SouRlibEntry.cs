
namespace SouRLib;

public class SouRlibEntry : IDisposable
{
    private readonly SouRLib Lib;

    public enum SouRLibScanResult
    {
        Safe,
        Worm,
        Virus,
        Trojan,
        Packed,
        Hoax,
        HackTool,
        Exploit,
        DangerousObject,
        Backdoor,
    }

    public SouRlibEntry()
    {
        Lib = new();
    }

    public bool Initialize() => Lib.Initialize(".\\SouXiao\\SouRLib\\");

    public List<SouRLibScanResult> ScanFile(string filePath)
    {
        List<YaraScanner.YaraMatch> Results = Lib.ScanFile(filePath);
        List<SouRLibScanResult> ScanResults = [];
        foreach (YaraScanner.YaraMatch result in Results)
        {
            String RuleHitName = result.RuleName.ToLower();
            if (RuleHitName.Contains("worm"))             ScanResults.Add(SouRLibScanResult.Worm);
            if (RuleHitName.Contains("trojan"))           ScanResults.Add(SouRLibScanResult.Trojan);
            if (RuleHitName.Contains("virus"))            ScanResults.Add(SouRLibScanResult.Virus);
            if (RuleHitName.Contains("packed"))           ScanResults.Add(SouRLibScanResult.Packed);
            if (RuleHitName.Contains("hoax"))             ScanResults.Add(SouRLibScanResult.Hoax);
            if (RuleHitName.Contains("hacktool"))         ScanResults.Add(SouRLibScanResult.HackTool);
            if (RuleHitName.Contains("exploit"))          ScanResults.Add(SouRLibScanResult.Exploit);
            if (RuleHitName.Contains("dangerousobject"))  ScanResults.Add(SouRLibScanResult.DangerousObject);
            if (RuleHitName.Contains("backdoor"))         ScanResults.Add(SouRLibScanResult.Backdoor);
            
        }
        if (ScanResults.Count == 0) ScanResults.Add(SouRLibScanResult.Safe);
        return ScanResults;
    }

    public int ProcessRules() => Lib.ProcessRules();

    public void Dispose()
    {
        Lib?.Dispose();
        GC.SuppressFinalize(this);
    }
}
