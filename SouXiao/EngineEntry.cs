using LiuLiAVHeuristic;
using PublicPart;
using SouRLib;

namespace SouXiao
{
    public class EngineEntry
    {
        public enum EngineStatus
        {
            UnLoad,
            Loaded,
            Runnting,
            Stopped,
        }

        private readonly Dictionary<String,EngineStatus> EStatuses = [];
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
                EObject["SouRLib"].Initialize(".\\SouXiao\\SouRLib\\");
                EStatuses["SouRLib"] = EngineStatus.Loaded;
                return true;
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
