using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);

// Basic server settings (can be configured via environment variables)
var storageRoot = builder.Configuration["VIDEO_STORAGE_ROOT"]
                  ?? Path.Combine(AppContext.BaseDirectory, "storage");
var maxUploadBytes = long.TryParse(builder.Configuration["MAX_UPLOAD_BYTES"], out var parsed)
    ? parsed
    : 2L * 1024 * 1024 * 1024; // 2 GiB default

Directory.CreateDirectory(storageRoot);

builder.Services.Configure<FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = maxUploadBytes;
});

var app = builder.Build();

app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine($"Storage: {storageRoot}");
    Console.WriteLine($"Max upload bytes: {maxUploadBytes:N0}");
});

// ---- Simple JSON index for metadata persistence ----
var indexPath = Path.Combine(storageRoot, "index.json");
var index = await VideoIndex.LoadAsync(indexPath);

app.MapGet("/", () => Results.Redirect("/docs"));

app.MapGet("/docs", () => Results.Text(@"Video Upload/Download API

POST   /videos                 Upload a video (multipart/form-data, field name: file)
GET    /videos                 List uploaded videos (metadata)
GET    /videos/{id}            Get metadata for a video
GET    /videos/{id}/download   Download/stream a video (supports Range)
HEAD   /videos/{id}/download   Get headers for a video resource
DELETE /videos/{id}            Delete a video and its metadata

Env:
  VIDEO_STORAGE_ROOT  - folder to store videos and index.json (default: ./storage)
  MAX_UPLOAD_BYTES    - max upload size in bytes (default: 2147483648 = 2 GiB)
", "text/plain"));

// Upload endpoint
app.MapPost("/videos", async (HttpRequest req) =>
{
    if (!req.HasFormContentType) return Results.BadRequest("Content-Type must be multipart/form-data");
    var form = await req.ReadFormAsync();
    var file = form.Files.GetFile("file");
    if (file is null) return Results.BadRequest("No file named 'file' found in form data.");

    if (file.Length == 0) return Results.BadRequest("Empty file.");
    if (file.Length > maxUploadBytes) return Results.BadRequest($"File too large. Limit: {maxUploadBytes} bytes.");

    // Best-effort validation
    var contentType = string.IsNullOrWhiteSpace(file.ContentType) ? "application/octet-stream" : file.ContentType;
    if (!contentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase))
    {
        // Allow some common cases where browsers send octet-stream
        var okExts = new[] { ".mp4", ".mov", ".m4v", ".mkv", ".webm", ".avi", ".ts", ".m2ts" };
        if (!okExts.Contains(Path.GetExtension(file.FileName).ToLowerInvariant()))
            return Results.BadRequest($"Unsupported content type '{contentType}'. Upload a video file.");
    }

    var id = Guid.NewGuid().ToString("n");
    var storedFileName = id + Path.GetExtension(file.FileName);
    var storedPath = Path.Combine(storageRoot, storedFileName);

    string sha256Hex;
    long totalBytes = 0;

    await using (var input = file.OpenReadStream())
    await using (var output = File.Create(storedPath))
    using (var sha = SHA256.Create())
    {
        var buffer = ArrayPool<byte>.Shared.Rent(1024 * 1024);
        try
        {
            int read;
            while ((read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length))) > 0)
            {
                await output.WriteAsync(buffer.AsMemory(0, read));
                sha.TransformBlock(buffer, 0, read, null, 0);
                totalBytes += read;
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            sha256Hex = Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    var record = new VideoRecord
    {
        Id = id,
        OriginalFileName = file.FileName,
        StoredFileName = storedFileName,
        Size = totalBytes,
        ContentType = contentType,
        UploadedAt = DateTimeOffset.UtcNow,
        Sha256Hex = sha256Hex
    };

    index.Upsert(record);
    await index.SaveAsync(indexPath);

    var location = $"/videos/{id}";
    return Results.Created(location, record);
})
.DisableAntiforgery();

// List videos
app.MapGet("/videos", () => Results.Json(index.All()))
   .Produces<IEnumerable<VideoRecord>>(statusCode: 200);

// Get metadata
app.MapGet("/videos/{id}", (string id) =>
{
    if (!index.TryGet(id, out var rec)) return Results.NotFound();
    return Results.Json(rec);
});

// Delete video
app.MapDelete("/videos/{id}", async (string id) =>
{
    if (!index.TryRemove(id, out var rec)) return Results.NotFound();
    var path = Path.Combine(storageRoot, rec.StoredFileName);
    if (File.Exists(path)) File.Delete(path);
    await index.SaveAsync(indexPath);
    return Results.NoContent();
});

// HEAD returns content metadata for download resource
app.MapMethods("/videos/{id}/download", new[] { "HEAD" }, (HttpResponse res, string id) =>
{
    if (!index.TryGet(id, out var rec)) return Results.NotFound();
    var path = Path.Combine(storageRoot, rec.StoredFileName);
    if (!File.Exists(path)) return Results.NotFound();

    var headers = new HeaderDictionary
    {
        ["Accept-Ranges"] = "bytes",
        ["Content-Length"] = rec.Size.ToString(CultureInfo.InvariantCulture),
        ["Content-Type"] = rec.ContentType,
        ["ETag"] = ETag(rec)
    };
    return Results.StatusCode(200);
});

// Download with Range support
app.MapGet("/videos/{id}/download", async (HttpRequest req, HttpResponse res, string id) =>
{
    if (!index.TryGet(id, out var rec)) return Results.NotFound();
    var path = Path.Combine(storageRoot, rec.StoredFileName);
    if (!File.Exists(path)) return Results.NotFound();

    res.Headers["Accept-Ranges"] = "bytes";
    res.Headers["ETag"] = ETag(rec);

    // If-Range / If-None-Match support (simple ETag handling)
    if (req.Headers.TryGetValue("If-None-Match", out var inm) && inm.ToString().Trim() == ETag(rec))
    {
        res.StatusCode = StatusCodes.Status304NotModified;
        return Results.Empty;
    }

    var fileLength = rec.Size;
    var rangeHeader = req.Headers["Range"].ToString();

    if (string.IsNullOrEmpty(rangeHeader))
    {
        res.ContentType = rec.ContentType;
        res.ContentLength = fileLength;
        await SendWholeAsync(res, path);
        return Results.Empty;
    }

    if (!TryParseRange(rangeHeader, fileLength, out var start, out var end))
    {
        res.StatusCode = StatusCodes.Status416RangeNotSatisfiable;
        res.Headers["Content-Range"] = $"bytes */{fileLength}";
        return Results.Empty;
    }

    var length = end - start + 1;
    res.StatusCode = StatusCodes.Status206PartialContent;
    res.ContentType = rec.ContentType;
    res.ContentLength = length;
    res.Headers["Content-Range"] = $"bytes {start}-{end}/{fileLength}";

    await SendRangeAsync(res, path, start, length);
    return Results.Empty;
});

app.Run();

static async Task SendWholeAsync(HttpResponse res, string path)
{
    await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.Asynchronous | FileOptions.SequentialScan);
    var buffer = ArrayPool<byte>.Shared.Rent(1 << 20);
    try
    {
        int read;
        while ((read = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length))) > 0)
        {
            await res.Body.WriteAsync(buffer.AsMemory(0, read));
        }
    }
    finally
    {
        ArrayPool<byte>.Shared.Return(buffer);
    }
}

static async Task SendRangeAsync(HttpResponse res, string path, long start, long length)
{
    await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.Asynchronous | FileOptions.RandomAccess);
    fs.Seek(start, SeekOrigin.Begin);

    var remaining = length;
    var buffer = ArrayPool<byte>.Shared.Rent(1 << 20);
    try
    {
        while (remaining > 0)
        {
            var toRead = (int)Math.Min(buffer.Length, remaining);
            var read = await fs.ReadAsync(buffer.AsMemory(0, toRead));
            if (read <= 0) break;
            await res.Body.WriteAsync(buffer.AsMemory(0, read));
            remaining -= read;
        }
    }
    finally
    {
        ArrayPool<byte>.Shared.Return(buffer);
    }
}

static bool TryParseRange(string rangeHeader, long fileLength, out long start, out long end)
{
    start = 0; end = fileLength - 1;
    // Expecting: bytes=start-end
    if (!rangeHeader.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) return false;
    var parts = rangeHeader[6..].Split('-', 2);
    if (parts.Length != 2) return false;

    var startStr = parts[0].Trim();
    var endStr = parts[1].Trim();

    if (startStr.Length == 0)
    {
        // suffix range: bytes=-N
        if (!long.TryParse(endStr, out var suffixLength) || suffixLength <= 0) return false;
        if (suffixLength > fileLength) suffixLength = fileLength;
        start = fileLength - suffixLength;
        end = fileLength - 1;
        return true;
    }

    if (!long.TryParse(startStr, out start)) return false;
    if (start < 0 || start >= fileLength) return false;

    if (endStr.Length == 0)
    {
        end = fileLength - 1;
        return true;
    }

    if (!long.TryParse(endStr, out end)) return false;
    if (end < start || end >= fileLength) return false;
    return true;
}

static string ETag(VideoRecord rec)
{
    // Weak ETag derived from checksum + size
    return $"\"{rec.Sha256Hex}:{rec.Size}\"";
}

public sealed class VideoIndex
{
    private readonly ConcurrentDictionary<string, VideoRecord> _map = new();

    public IEnumerable<VideoRecord> All() => _map.Values.OrderByDescending(v => v.UploadedAt);

    public bool TryGet(string id, out VideoRecord record) => _map.TryGetValue(id, out record!);
    public bool TryRemove(string id, out VideoRecord record) => _map.TryRemove(id, out record!);

    public void Upsert(VideoRecord record) => _map[record.Id] = record;

    public async Task SaveAsync(string path)
    {
        var dto = _map.Values.ToArray();
        var json = JsonSerializer.Serialize(dto, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        await File.WriteAllTextAsync(path, json, Encoding.UTF8);
    }

    public static async Task<VideoIndex> LoadAsync(string path)
    {
        var idx = new VideoIndex();
        if (!File.Exists(path)) return idx;
        try
        {
            var json = await File.ReadAllTextAsync(path, Encoding.UTF8);
            var items = JsonSerializer.Deserialize<VideoRecord[]>(json) ?? Array.Empty<VideoRecord>();
            foreach (var it in items) idx.Upsert(it);
        }
        catch
        {
            // ignore corrupted index; start fresh
        }
        return idx;
    }
}

public sealed record VideoRecord
{
    public required string Id { get; init; }
    public required string OriginalFileName { get; init; }
    public required string StoredFileName { get; init; }
    public required long Size { get; init; }
    public required string ContentType { get; init; }
    public required DateTimeOffset UploadedAt { get; init; }
    public required string Sha256Hex { get; init; }
}
