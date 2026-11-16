// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Rustegon.Driver.Errors;

namespace Rustegon.Driver.Internal.Auth;

/// <summary>
/// SCRAM-SHA-256 client state machine (RFC 5802, RFC 7677; protocol.md §8). Mirrors
/// <c>crates/rustegon-security/src/authn/scram/client.rs</c>: gs2 header <c>n,,</c> (no channel
/// binding, PD-074), 24-character base62 nonce, iteration bounds 4096..=10 000 000, mutual
/// authentication by verifying the server signature.
/// </summary>
/// <remarks>
/// Not thread-safe: one instance serves one handshake, in order (<see cref="ClientFirst"/>,
/// <see cref="ProcessServerFirst"/>, <see cref="VerifyServerFinal"/>). Key material is zeroed as
/// soon as it is no longer needed; the password string itself cannot be zeroed (immutable .NET
/// string), which is why the credential keeps it private and never logs it.
/// </remarks>
internal sealed class ScramSha256Client
{
    /// <summary>gs2 header: no channel binding, no authzid (PD-074).</summary>
    internal const string Gs2Header = "n,,";

    /// <summary>RFC 7677 §4: at least 4096; lower is a downgrade attempt.</summary>
    internal const int MinIterations = 4096;

    /// <summary>Bound against a malicious server making the client spin for minutes.</summary>
    internal const int MaxIterations = 10_000_000;

    /// <summary>Largest accepted server message (bounds parsing work on untrusted input).</summary>
    internal const int MaxMessageLength = 4096;

    /// <summary>24 base62 characters ≈ 143 bits.</summary>
    private const int NonceLength = 24;

    private const string Base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private readonly string _password;
    private readonly string _clientNonce;
    private readonly string _bare;
    private byte[]? _serverSignature;

    /// <summary>Starts a handshake.</summary>
    /// <param name="user">User name (SASL-escaped here, not prepared, as the Rust client).</param>
    /// <param name="password">Password (SASLprep is applied when deriving the key).</param>
    /// <param name="nonce">Client nonce; random when null (tests pass the RFC vector's nonce).</param>
    internal ScramSha256Client(string user, string password, string? nonce = null)
    {
        _password = password;
        _clientNonce = nonce ?? RandomNumberGenerator.GetString(Base62, NonceLength);
        _bare = "n=" + EncodeSaslName(user) + ",r=" + _clientNonce;
    }

    /// <summary>The client-first message.</summary>
    internal string ClientFirst => Gs2Header + _bare;

    /// <summary>Processes server-first and returns client-final (CPU bound: PBKDF2).</summary>
    /// <exception cref="AuthenticationException">Malformed message, nonce not extending ours, iteration count out of bounds, password invalid for SASLprep.</exception>
    internal string ProcessServerFirst(string serverFirst)
    {
        if (serverFirst.Length > MaxMessageLength)
        {
            throw Fail("server-first message too long");
        }

        string[] attrs = serverFirst.Split(',');
        if (attrs.Length != 3)
        {
            throw Fail("malformed server-first message");
        }

        string nonce = Attr(attrs[0], 'r');
        byte[] salt = DecodeBase64(Attr(attrs[1], 's'));
        if (!int.TryParse(Attr(attrs[2], 'i'), NumberStyles.None, CultureInfo.InvariantCulture, out int iterations)
            || iterations is < MinIterations or > MaxIterations)
        {
            throw Fail("iteration count out of bounds");
        }

        if (!ValidNonce(nonce) || nonce.Length <= _clientNonce.Length || !nonce.StartsWith(_clientNonce, StringComparison.Ordinal) || salt.Length == 0)
        {
            throw Fail("malformed server-first message");
        }

        if (!SaslPrep.TryPrepare(_password, out string prepared))
        {
            throw Fail("the password is not valid SASLprep text");
        }

        byte[] passwordBytes = Encoding.UTF8.GetBytes(prepared);
        byte[] salted = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, 32);
        CryptographicOperations.ZeroMemory(passwordBytes);
        byte[] clientKey = HMACSHA256.HashData(salted, "Client Key"u8);
        byte[] storedKey = SHA256.HashData(clientKey);
        byte[] serverKey = HMACSHA256.HashData(salted, "Server Key"u8);
        CryptographicOperations.ZeroMemory(salted);

        string withoutProof = "c=" + Convert.ToBase64String(Encoding.ASCII.GetBytes(Gs2Header)) + ",r=" + nonce;
        byte[] authMessage = Encoding.UTF8.GetBytes(_bare + "," + serverFirst + "," + withoutProof);
        byte[] signature = HMACSHA256.HashData(storedKey, authMessage);
        byte[] proof = new byte[clientKey.Length];
        for (int i = 0; i < proof.Length; i++)
        {
            proof[i] = (byte)(clientKey[i] ^ signature[i]);
        }

        CryptographicOperations.ZeroMemory(clientKey);
        _serverSignature = HMACSHA256.HashData(serverKey, authMessage);
        CryptographicOperations.ZeroMemory(serverKey);
        string clientFinal = withoutProof + ",p=" + Convert.ToBase64String(proof);
        CryptographicOperations.ZeroMemory(proof);
        return clientFinal;
    }

    /// <summary>Verifies server-final: proves the server knows the credentials (mutual authentication).</summary>
    /// <exception cref="AuthenticationException"><c>e=…</c>, a malformed message or a wrong signature.</exception>
    internal void VerifyServerFinal(string serverFinal)
    {
        if (_serverSignature is null)
        {
            throw new InvalidOperationException("server-first has not been processed");
        }

        if (serverFinal.Length > MaxMessageLength || !serverFinal.StartsWith("v=", StringComparison.Ordinal))
        {
            throw Fail("server signature missing");
        }

        byte[] sig = DecodeBase64(serverFinal[2..]);
        if (!CryptographicOperations.FixedTimeEquals(sig, _serverSignature))
        {
            throw Fail("server signature mismatch");
        }
    }

    /// <summary>RFC 5802 §5.1 saslname: <c>=</c> → <c>=3D</c>, <c>,</c> → <c>=2C</c>.</summary>
    internal static string EncodeSaslName(string s) =>
        s.Replace("=", "=3D", StringComparison.Ordinal).Replace(",", "=2C", StringComparison.Ordinal);

    /// <summary>RFC 5802 §7: <c>printable = %x21-2B / %x2D-7E</c>.</summary>
    private static bool ValidNonce(string n)
    {
        if (n.Length == 0)
        {
            return false;
        }

        foreach (char c in n)
        {
            if (c is < (char)0x21 or > (char)0x7E or ',')
            {
                return false;
            }
        }

        return true;
    }

    private static string Attr(string part, char key) =>
        part.Length >= 2 && part[0] == key && part[1] == '=' ? part[2..] : throw Fail("malformed SCRAM message");

    private static byte[] DecodeBase64(string s)
    {
        byte[] buffer = new byte[((s.Length / 4) + 1) * 3];
        return s.Length % 4 == 0 && Convert.TryFromBase64String(s, buffer, out int written)
            ? buffer.AsSpan(0, written).ToArray()
            : throw Fail("malformed base64 in SCRAM message");
    }

    private static AuthenticationException Fail(string reason) =>
        new(RustegonError.Client(ErrorCodes.Unauthenticated), "authentication failed: " + reason);
}
