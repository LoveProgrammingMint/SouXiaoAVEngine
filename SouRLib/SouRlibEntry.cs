using PublicPart;
namespace SouRLib;

public class SouRlibEntry : IDisposable, IEngineEntry
{
    private readonly SouRLib Lib;
    public String VERSION { get; set; } = "5.22.1";

    public SouRlibEntry()
    {
        Lib = new();
    }

    public bool Initialize(String Path) => Lib.Initialize(Path); // ".\\SouXiao\\SouRLib\\"

    public List<EngineResult> Scan(bool IsPE,string? Path)
    {
        if (string.IsNullOrEmpty(Path)) throw new InvalidOperationException("Callback can't use this engine");
        if (!IsPE) return [EngineResult.Safe];


        List<YaraScanner.YaraMatch> Results = Lib.ScanFile(Path);
        List<EngineResult> ScanResults = [];
        foreach (YaraScanner.YaraMatch result in Results)
        {
            String RuleHitName = result.RuleName.ToLower();
            if (RuleHitName.Contains("worm"))             ScanResults.Add(EngineResult.Worm);
            if (RuleHitName.Contains("trojan"))           ScanResults.Add(EngineResult.Trojan);
            if (RuleHitName.Contains("virus"))            ScanResults.Add(EngineResult.Virus);
            if (RuleHitName.Contains("packed"))           ScanResults.Add(EngineResult.Packed);
            if (RuleHitName.Contains("hoax"))             ScanResults.Add(EngineResult.Hoax);
            if (RuleHitName.Contains("hacktool"))         ScanResults.Add(EngineResult.HackTool);
            if (RuleHitName.Contains("exploit"))          ScanResults.Add(EngineResult.Exploit);
            if (RuleHitName.Contains("dangerousobject"))  ScanResults.Add(EngineResult.DangerousObject);
            if (RuleHitName.Contains("backdoor"))         ScanResults.Add(EngineResult.Backdoor);
            
        }
        if (ScanResults.Count == 0) ScanResults.Add(EngineResult.Safe);
        else ScanResults.Add(EngineResult.Malicious);
            return ScanResults;
    }

    public int ProcessRules() => Lib.ProcessRules();

    public void Dispose()
    {
        Lib?.Dispose();
        GC.SuppressFinalize(this);
    }
}
