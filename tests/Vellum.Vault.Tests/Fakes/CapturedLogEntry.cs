using Microsoft.Extensions.Logging;

namespace Vellum.Vault.Tests.Fakes;

/// <summary>
/// Represents a single log entry captured by <see cref="CapturingLogger{T}"/>.
/// </summary>
public sealed record CapturedLogEntry(LogLevel Level, EventId EventId, string Message, Exception? Exception);
