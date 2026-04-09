using System.Text.Json.Serialization;

namespace Vellum.Vault.Internal;

/// <summary>
/// System.Text.Json source-generated context for Vault Transit request and response DTOs.
/// </summary>
/// <remarks>
/// Source generation keeps the hot path allocation-free and makes the library trim / AOT friendly.
/// Any new DTO added to the <see cref="Internal"/> namespace must be registered here via
/// <see cref="JsonSerializableAttribute"/>.
/// </remarks>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(VaultEncryptRequest))]
[JsonSerializable(typeof(VaultEncryptResponse))]
[JsonSerializable(typeof(VaultEncryptResponseData))]
[JsonSerializable(typeof(VaultDecryptRequest))]
[JsonSerializable(typeof(VaultDecryptResponse))]
[JsonSerializable(typeof(VaultDecryptResponseData))]
internal sealed partial class VaultJsonContext : JsonSerializerContext;
