using LiuLiAVHeuristic;
using PeNet;
using PublicPart;
using SouRLib;
using System.Diagnostics;

namespace SouXiao;

public class EngineEntry
{
    public enum EngineStatus
    {
        UnLoad,
        Loaded,
        Runnting,
        Stopped,
    }

    private readonly Dictionary<String, EngineStatus> EStatuses = [];
    private readonly Dictionary<String, IEngineEntry> EObject = [];

    public EngineEntry()
    {
        //LiuLi AV Engine
        EStatuses.Add("LiuLiAV", EngineStatus.UnLoad);
        EObject.Add("LiuLiAV", new LiuLiEntry());

        //Sou Rule Lib
        EStatuses.Add("SouRLib", EngineStatus.UnLoad);
        EObject.Add("SouRLib", new SouRlibEntry());
    }

    public Boolean Initialize()
    {
        try
        {
            EObject["LiuLiAV"].Initialize(".\\LiuLi.onnx");
            EStatuses["LiuLiAV"] = EngineStatus.Loaded;
            //EObject["SouRLib"].Initialize(".\\SouXiao\\SouRLib\\");
            //EStatuses["SouRLib"] = EngineStatus.Loaded;
            return true;
        }
        catch (Exception)
        {
            throw;
        }
    }

    public Dictionary<String, List<EngineResult>> Scan(String Path)
    {
        Boolean IsPE = PeFile.IsPeFile(Path);
        Dictionary<String, List<EngineResult>> Result = [];
        foreach (var item in EObject)
        {
            if (EStatuses[item.Key] == EngineStatus.Loaded)
            {
                Result.Add(item.Key, item.Value.Scan(IsPE,Path));
            }
        }
        return Result;
    }

    //public Dictionary<String, List<EngineResult>> Scan(Byte[] Data)
    //{
    //    Boolean IsPE = PeFile.IsPeFile(Data);
    //    Dictionary<String, List<EngineResult>> Result = [];
    //    foreach (var item in EObject)
    //    {
    //        if (EStatuses[item.Key] == EngineStatus.Loaded)
    //        {
    //            Result.Add(item.Key, item.Value.Scan(IsPE, ""));
    //        }
    //    }
    //    return Result;
    //}

    //public Dictionary<String, List<EngineResult>> Scan(FileStream FileStream)
    //{
    //    return [];
    //}

    //public Dictionary<String, List<EngineResult>> Scan(Stream Stream)
    //{
    //    return [];
    //}

    //public Dictionary<String, List<EngineResult>> Scan(PeFile File)
    //{
    //    return [];
    //}

    //public Dictionary<String, List<EngineResult>> Scan(Process FileProcess)
    //{
    //    return [];
    //}


}

