using System.CodeDom.Compiler;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using SshCert.Cli;

namespace SshCert.Tests;

[CollectionDefinition("Console output", DisableParallelization = true)]
public sealed class ConsoleOutputCollection;

[Collection("Console output")]
public class ConventionTests
{
    [Fact]
    public void SourceDeclaredPrivateFieldsUseUnderscoreCamelCase()
    {
        var assemblies = new[] { typeof(Application).Assembly, typeof(ConventionTests).Assembly };
        var fields = assemblies.SelectMany(assembly => assembly.GetTypes())
            .Where(type => !IsGenerated(type))
            .SelectMany(type => type.GetFields(BindingFlags.NonPublic | BindingFlags.Instance |
                BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Where(field => field.IsPrivate && !field.IsDefined(typeof(CompilerGeneratedAttribute)));
        Assert.All(fields, field =>
            Assert.Matches("^_[a-z][A-Za-z0-9]*$", field.Name));
    }

    [Fact]
    public void RetainedConstructorDependenciesUseExplicitFields()
    {
        var fields = typeof(Application).Assembly.GetTypes()
            .Where(type => !IsGenerated(type))
            .SelectMany(type => type.GetFields(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly));
        Assert.DoesNotContain(fields, field => field.Name.EndsWith(">P", StringComparison.Ordinal));
    }

    [Fact]
    public void RuntimeVersionMatchesSdkAssemblyMetadata()
    {
        var assembly = typeof(Application).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!;
        Assert.Equal(informational.InformationalVersion.Split('+')[0], Application.Version);
        Assert.Equal(assembly.GetName().Version!.ToString(3), Application.Version);
        Assert.Matches(@"^\d+\.\d+\.\d+$", Application.Version);
    }

    [Theory]
    [InlineData("--version", 0)]
    [InlineData("--help", 0)]
    [InlineData("-h", 0)]
    [InlineData("--unknown", 2)]
    [InlineData("--group", 2)]
    public async Task VersionBannerIsFirstAndAppearsExactlyOnce(string argument, int expectedExit)
    {
        var lines = new List<(string Channel, string Text)>();
        var originalOut = Console.Out;
        var originalError = Console.Error;
        using var output = new RecordingWriter(lines, "out");
        using var error = new RecordingWriter(lines, "error");
        try
        {
            Console.SetOut(output);
            Console.SetError(error);
            Assert.Equal(expectedExit, await Application.Run([argument]));
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
        var banner = "ssh-cert " + typeof(Application).Assembly.GetName().Version!.ToString(3);
        Assert.Equal(("out", banner), lines[0]);
        Assert.Single(lines, line => line.Text == banner);
        if (argument == "--version") Assert.Single(lines);
        if (expectedExit != 0) Assert.Contains(lines.Skip(1), line => line.Channel == "error");
    }

    private static bool IsGenerated(Type? type) => type is not null &&
        (type.IsDefined(typeof(CompilerGeneratedAttribute)) || type.IsDefined(typeof(GeneratedCodeAttribute)) ||
            IsGenerated(type.DeclaringType));

    private sealed class RecordingWriter(List<(string Channel, string Text)> lines, string channel) : TextWriter
    {
        private readonly List<(string Channel, string Text)> _lines = lines;
        private readonly string _channel = channel;

        public override Encoding Encoding => Encoding.UTF8;
        public override void WriteLine(string? value) => _lines.Add((_channel, value ?? ""));
    }
}
