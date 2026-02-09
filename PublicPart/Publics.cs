namespace PublicPart
{
    public interface IEngineEntry
    {
        public String VERSION { get; set; }
        public Boolean Initialize(string Path);
        public List<EngineResult> Scan(Boolean IsPE, String? FilePath);
        public void Dispose();
    }

    public enum EngineResult
    {
        // Simple
        Safe,
        Malicious,
        UnSupport,

        // for SouRLib
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
}
