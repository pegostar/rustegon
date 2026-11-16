// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Rustegon.Driver.Mapping;

/// <summary>Maps <typeparamref name="T"/> to and from an <see cref="RDocument"/> (dotnet-driver.md §7).</summary>
/// <typeparam name="T">The mapped type.</typeparam>
public interface IRDocCodec<T>
{
    /// <summary>The document of a value.</summary>
    /// <param name="value">The value (not null).</param>
    /// <returns>The document.</returns>
    /// <exception cref="RDocException">A member cannot be mapped (RGN-1001).</exception>
    RDocument Encode(T value);

    /// <summary>The value of a document. Fields without a member are ignored (PD-108).</summary>
    /// <param name="document">The document.</param>
    /// <returns>The value.</returns>
    /// <exception cref="RDocException">A field cannot be mapped (RGN-1001).</exception>
    T Decode(RDocument document);
}

/// <summary>
/// The codecs of mapped types. Codecs generated for <see cref="RustegonDocumentAttribute"/> types
/// register themselves from a module initializer of the assembly that declares the type; the
/// reflection fallback is used only after <see cref="EnableReflectionFallback"/>. Typed handles
/// (<see cref="IRustegonDatabase.GetCollection{T}"/>, <see cref="ITransaction.Collection{T}"/>)
/// resolve their codec here when they are created, so an unmapped type fails there, before any I/O.
/// </summary>
public static class RDocCodecRegistry
{
    private static Func<Type, object>? s_fallback;

    /// <summary>Whether <see cref="EnableReflectionFallback"/> was called.</summary>
    public static bool IsReflectionFallbackEnabled => Volatile.Read(ref s_fallback) is not null;

    /// <summary>Registers (or replaces) the codec of <typeparamref name="T"/>; generated code calls it.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <param name="codec">The codec.</param>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public static void Register<T>(IRDocCodec<T> codec)
    {
        ArgumentNullException.ThrowIfNull(codec);
        Volatile.Write(ref Slot<T>.Codec, codec);
    }

    /// <summary>
    /// Opts in to the reflection codec for types without a generated codec (process-wide). It reads
    /// the same attributes and follows the same rules as the generator, but it is neither trimming
    /// nor AOT safe.
    /// </summary>
    [RequiresUnreferencedCode("The reflection codec reads the members of mapped types at run time; use [RustegonDocument] with the source generator instead.")]
    [RequiresDynamicCode("The reflection codec builds generic converters at run time; use [RustegonDocument] with the source generator instead.")]
    public static void EnableReflectionFallback() => Volatile.Write(ref s_fallback, ReflectionCodec.Create);

    /// <summary>Turns the fallback off again (tests only; codecs already created stay registered).</summary>
    internal static void DisableReflectionFallback() => Volatile.Write(ref s_fallback, null);

    /// <summary>The codec of <typeparamref name="T"/>: the registered (generated) one, else the reflection one when enabled.</summary>
    /// <typeparam name="T">The mapped type.</typeparam>
    /// <returns>The codec.</returns>
    /// <exception cref="NotSupportedException">No codec: <typeparamref name="T"/> is not a <see cref="RustegonDocumentAttribute"/> type and the fallback is off, or the reflection codec cannot map it.</exception>
    public static IRDocCodec<T> Get<T>()
    {
        if (Volatile.Read(ref Slot<T>.Codec) is { } codec)
        {
            return codec;
        }

        if (typeof(T) == typeof(RDocument))
        {
            return (IRDocCodec<T>)(object)IdentityCodec.Instance;
        }

        // Referencing a type as a generic argument does not run the module initializer of its
        // assembly; the generated registration lives there, so run it now (a no-op once it ran).
        RuntimeHelpers.RunModuleConstructor(typeof(T).Module.ModuleHandle);
        if (Volatile.Read(ref Slot<T>.Codec) is { } generated)
        {
            return generated;
        }

        if (Volatile.Read(ref s_fallback) is { } fallback)
        {
            var reflected = (IRDocCodec<T>)fallback(typeof(T));
            return Interlocked.CompareExchange(ref Slot<T>.Codec, reflected, null) ?? reflected;
        }

        throw new NotSupportedException(
            $"No codec for {typeof(T).FullName}: mark it [RustegonDocument] (the source generator of Rustegon.Driver emits the codec) "
            + "or opt in to RDocCodecRegistry.EnableReflectionFallback().");
    }

    private static class Slot<T>
    {
#pragma warning disable CA1802, SA1401 // a mutable static slot per type is the point (read with Volatile)
        internal static IRDocCodec<T>? Codec;
#pragma warning restore CA1802, SA1401
    }

    private sealed class IdentityCodec : IRDocCodec<RDocument>
    {
        internal static readonly IdentityCodec Instance = new();

        public RDocument Encode(RDocument value) => value ?? throw new ArgumentNullException(nameof(value));

        public RDocument Decode(RDocument document) => document;
    }
}
