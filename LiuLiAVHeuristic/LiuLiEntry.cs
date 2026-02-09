using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PeNet;
using PublicPart;
using System.Buffers;

namespace LiuLiAVHeuristic;


public class LiuLiEntry : IDisposable, IEngineEntry
{
    private InferenceSession? _session;
    private readonly DenseTensor<float> _inputTensor = new([1, 3, 64, 64]);
    private const int INPUT_SIZE = 3 * 64 * 64;
    public String VERSION { get; set; } = "5.22.1";

    public Boolean Initialize(string Path)
    {
        try
        {
            _session = new(Path);
            return true;
        }
        catch 
        {
            return false;
        }
    }


    public List<EngineResult> Scan(Boolean IsPE,String? FilePath)
    {
        if (_session == null || String.IsNullOrEmpty(FilePath))
            throw new InvalidOperationException("Callback can't use this engine");

        if (!IsPE) return [EngineResult.UnSupport];
        var bytePool = ArrayPool<byte>.Shared;
        byte[] byteBuffer = bytePool.Rent(INPUT_SIZE);

        try
        {

            using var fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, FileOptions.SequentialScan);
            int bytesRead = fs.Read(byteBuffer, 0, INPUT_SIZE);

            for (int i = bytesRead; i < INPUT_SIZE; i++)
                byteBuffer[i] = 0;

            var tensorSpan = _inputTensor.Buffer.Span;
            for (int i = 0; i < INPUT_SIZE; i++)
                tensorSpan[i] = byteBuffer[i] / 255.0f;

            var inputs = new[]
            {
        NamedOnnxValue.CreateFromTensor(_session.InputNames[0], _inputTensor)
    };

            using var results = _session.Run(inputs);
            var output = results[0].AsTensor<float>();

            var logits = (Span<float>)[output[0, 0], output[0, 1]];
            var max = MathF.Max(logits[0], logits[1]);

            logits[0] = MathF.Exp(logits[0] - max);
            logits[1] = MathF.Exp(logits[1] - max);

            var sum = logits[0] + logits[1];
            logits[0] /= sum;
            logits[1] /= sum;

            return (logits[0] < 0.25f)? [EngineResult.Malicious] : [EngineResult.Safe] ;
        }
        finally
        {
            bytePool.Return(byteBuffer, false);
        }
    }
    public void Dispose()
    {
        _session?.Dispose();
        GC.SuppressFinalize(this);
    }
}