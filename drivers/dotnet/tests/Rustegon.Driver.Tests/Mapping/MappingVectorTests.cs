// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Rustegon.Driver.Internal.Json;
using Rustegon.Driver.Mapping;
using Rustegon.Driver.MappedTypes;
using Xunit;

namespace Rustegon.Driver.Tests.Mapping;

/// <summary>
/// TC-DRV-NET-023 (FR-DRV-001, PD-108…PD-110): the cross-driver mapping vectors of
/// <c>drivers/conformance/mapping/vectors.yaml</c>, through the generated codec and the
/// reflection codec; the Java runner reads the same file, so mapped data written by one driver
/// reads back in the other.
/// </summary>
public sealed class MappingVectorTests
{
    private static readonly string[] Sections = ["roundTrip", "build", "invalid"];

    private static Dictionary<string, object?> File() =>
        (Dictionary<string, object?>)ConformanceYaml.Load(Path.Combine(TestPaths.Conformance, "mapping", "vectors.yaml"))!;

    public static TheoryData<string, string> Vectors()
    {
        var data = new TheoryData<string, string>();
        Dictionary<string, object?> root = File();
        foreach (string section in Sections)
        {
            foreach (Dictionary<string, object?> v in ((List<object?>)root[section]!).Cast<Dictionary<string, object?>>())
            {
                data.Add(section, (string)v["name"]!);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void tc_drv_net_023_cross_driver_mapping_vectors(string section, string name)
    {
        Dictionary<string, object?> v = ((List<object?>)File()[section]!).Cast<Dictionary<string, object?>>()
            .Single(x => (string)x["name"]! == name);
        switch ((string)v["model"]!)
        {
            case "MapItem":
                Run<MapItem>(section, v);
                break;
            case "MapGeo":
                Run<MapGeo>(section, v);
                break;
            case "MapShape":
                Run<MapShape>(section, v);
                break;
            case "MapDrawing":
                Run<MapDrawing>(section, v);
                break;
            default:
                Assert.Fail($"unknown model {v["model"]}");
                break;
        }
    }

    private static void Run<T>(string section, Dictionary<string, object?> v)
    {
        foreach (IRDocCodec<T> codec in new IRDocCodec<T>[] { RDocCodecRegistry.Get<T>(), new ReflectionCodec<T>() })
        {
            string? json = v.GetValueOrDefault("json") as string;
            switch (section)
            {
                case "roundTrip":
                    AssertWrites(codec, codec.Decode(RDocJsonReader.ParseDocument(v.GetValueOrDefault("input") as string ?? json!)), json!);
                    AssertWrites(codec, codec.Decode(RDocJsonReader.ParseDocument(json!)), json!);
                    break;
                case "build":
                    AssertWrites(codec, (T)(object)Build((string)v["name"]!), json!);
                    break;
                default:
                    Assert.ThrowsAny<RDocException>(() => codec.Decode(RDocJsonReader.ParseDocument((string)v["input"]!)));
                    break;
            }
        }
    }

    private static void AssertWrites<T>(IRDocCodec<T> codec, T value, string json)
    {
        RDocument written = codec.Encode(value);
        Assert.Equal(json, written.ToJson());
        Assert.Equal(RDocJsonReader.ParseDocument(json).ToBytes(), written.ToBytes());
    }

    /// <summary>The <c>build</c> values, as their <c>value</c> text describes them.</summary>
    private static MapItem Build(string name) => name switch
    {
        "null_id_omitted_read_only_not_written" => new MapItem { Name = "n", Rev = "r1", Views = 99 },
        "datetime_rounded_down_to_ms" => new MapItem { Id = "t1", When = At("2026-11-12T10:15:30.1234567Z") },
        "datetime_rounded_down_before_1970" => new MapItem { Id = "t2", When = At("1969-12-31T23:59:59.9995Z") },
        "datetime_offset_dropped" => new MapItem { Id = "t3", When = At("2026-01-02T03:04:05.999+02:00") },
        "float_widened_to_float64" => new MapItem { Id = "f1", Ratio = 0.1f },
        _ => throw new InvalidOperationException($"unknown build vector {name}"),
    };

    private static DateTimeOffset At(string s) => DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.None);
}
