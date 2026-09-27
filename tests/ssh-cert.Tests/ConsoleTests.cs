using SshCert.ConsoleUi;
using SshCert.Cli;
using SshCert.Models;

namespace SshCert.Tests;

public sealed class FakeTerminal : ITerminal
{
    public int Width { get; set; } = 60;
    public int Height { get; set; } = 10;
    public int Top => 0;
    public int CursorTop { get; set; }
    public bool Visible { get; private set; } = true;
    public int Scrolled { get; private set; }
    public Queue<ConsoleKeyInfo> Keys { get; } = new();
    public Dictionary<int, string> Rows { get; } = [];
    public bool KeyAvailable => Keys.Count > 0;
    public ConsoleKeyInfo ReadKey() => Keys.Dequeue();
    public void Move(int column, int row)
    {
        Assert.InRange(column, 0, Width - 1);
        Assert.InRange(row, 0, Height - 1);
        CursorTop = row;
    }
    public void Write(string value)
    {
        if (value.All(c => c == '\n'))
        {
            foreach (var _ in value)
                if (CursorTop == Height - 1) Scrolled++; else CursorTop++;
        }
        else Rows[CursorTop] = value;
    }
    public void Cursor(bool visible) => Visible = visible;
    public void Key(ConsoleKey key, char character = '\0') => Keys.Enqueue(new ConsoleKeyInfo(character, key, false, false, false));
}

public class ConsoleTests
{
    [Fact]
    public void StartupShowsTheGroupMatchingExactlyTheEnabledConnections()
    {
        var first = new Remote { Enabled = true };
        var second = new Remote { Enabled = true };
        var disabled = new Remote();
        var state = new ConnectionFile { Connections = [first, second, disabled] };
        var groups = new[]
        {
            new Group { Name = "Subset", Connections = [first.Id] },
            new Group { Name = "Superset", Connections = [first.Id, second.Id, disabled.Id] },
            new Group { Name = "Office", Connections = [second.Id, first.Id] }
        };
        Assert.Equal("Active group: Office", Application.DescribeActiveGroup(state, groups));
    }

    [Fact]
    public void StartupDistinguishesCustomSelectionsEmptyGroupsAndNoGroups()
    {
        Assert.Equal("Active group: none (no enabled connections)",
            Application.DescribeActiveGroup(new ConnectionFile(), []));
        Assert.Equal("Active group: All off",
            Application.DescribeActiveGroup(new ConnectionFile(), [new Group { Name = "All off" }]));
        Assert.Equal("Active group: none (custom selection; 1 enabled)",
            Application.DescribeActiveGroup(new ConnectionFile { Connections = [new Remote { Enabled = true }] },
                [new Group { Name = "All off" }]));
    }

    [Fact]
    public void StartupDoesNotInventASingleActiveGroupWhenMembershipsAreIdentical()
    {
        var remote = new Remote { Enabled = true };
        Assert.Equal("Active group: multiple matches (First, Second)",
            Application.DescribeActiveGroup(new ConnectionFile { Connections = [remote] },
                [new Group { Name = "Second", Connections = [remote.Id] }, new Group { Name = "First", Connections = [remote.Id] }]));
    }

    [Theory]
    [InlineData(ConsoleKey.Enter, true)]
    [InlineData(ConsoleKey.Escape, false)]
    public void EnterConfirmsAndEscapeCancelsWithoutCheckboxes(ConsoleKey key, bool confirmed)
    {
        var terminal = new FakeTerminal { CursorTop = 9 };
        terminal.Key(key);
        var result = new Prompts(terminal, () => CancellationToken.None).Confirm("Import this connection?");
        Assert.Equal(confirmed, result);
        Assert.Contains(terminal.Rows.Values, row => row.Contains("Enter: confirm  Esc: cancel", StringComparison.Ordinal));
        Assert.DoesNotContain(terminal.Rows.Values, row => row.Contains("[ ]") || row.Contains("[X]") || row.Contains("type to filter"));
        Assert.True(terminal.Visible);
    }

    [Theory]
    [InlineData(ConsoleKey.Enter, true)]
    [InlineData(ConsoleKey.Escape, false)]
    public void OtherKeysDoNotChangeConfirmationAction(ConsoleKey key, bool confirmed)
    {
        var terminal = new FakeTerminal();
        terminal.Key(ConsoleKey.Spacebar, ' ');
        terminal.Key(ConsoleKey.A, 'a');
        terminal.Key(ConsoleKey.DownArrow);
        terminal.Key(key);
        Assert.Equal(confirmed, new Prompts(terminal, () => CancellationToken.None).Confirm("Continue?"));
        Assert.Empty(terminal.Keys);
    }

    [Fact]
    public void ControlCAbortsRatherThanDecliningAnOptionalConfirmation()
    {
        var terminal = new FakeTerminal();
        terminal.Keys.Enqueue(new ConsoleKeyInfo('c', ConsoleKey.C, false, false, true));
        Assert.Throws<OperationCanceledException>(() => new Prompts(terminal, () => CancellationToken.None).Confirm("Continue?"));
        Assert.True(terminal.Visible);
    }

    [Fact]
    public void CancellationTokenPreventsConfirmation()
    {
        var terminal = new FakeTerminal();
        terminal.Key(ConsoleKey.Enter);
        Assert.Throws<OperationCanceledException>(() => new Prompts(terminal, () => new CancellationToken(true)).Confirm("Continue?"));
        Assert.True(terminal.Visible);
    }

    [Fact]
    public void EmptyChecklistDoesNotPretendAFilterHidItsChoices()
    {
        var terminal = new FakeTerminal();
        terminal.Key(ConsoleKey.Enter);
        Assert.Empty(new Prompts(terminal, () => CancellationToken.None).Check("Group membership", []));
        Assert.Contains(terminal.Rows.Values, row => row.Contains("no choices available", StringComparison.Ordinal));
        Assert.DoesNotContain(terminal.Rows.Values, row => row.Contains("no matches", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(6, 2)]
    [InlineData(9, 5)]
    public void RegionReservesExactlyTheMissingBottomRows(int cursor, int scroll)
    {
        var terminal = new FakeTerminal { CursorTop = cursor };
        using (var region = new Region(terminal))
            region.Draw(["title", "one", "two", "three", "hint"]);
        Assert.Equal(scroll, terminal.Scrolled);
        Assert.True(terminal.Visible);
        Assert.Equal(5, terminal.Rows.Count);
    }

    [Fact]
    public void CheckboxesRetainSelectionAcrossFiltering()
    {
        var terminal = new FakeTerminal { CursorTop = 9 };
        terminal.Key(ConsoleKey.Spacebar, ' ');
        terminal.Key(ConsoleKey.B, 'b');
        terminal.Key(ConsoleKey.Spacebar, ' ');
        terminal.Key(ConsoleKey.Backspace);
        terminal.Key(ConsoleKey.Enter);
        var prompt = new Prompts(terminal, () => CancellationToken.None);
        Assert.Equal([0, 1], prompt.Check("Choose", ["alpha", "beta"]).Order().ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(6)]
    [InlineData(50)]
    public void MenuLengthsFitViewport(int count)
    {
        var terminal = new FakeTerminal { CursorTop = 9 };
        terminal.Key(ConsoleKey.End);
        terminal.Key(ConsoleKey.Enter);
        var prompt = new Prompts(terminal, () => CancellationToken.None);
        if (count == 0) Assert.Empty(prompt.Check("Empty", []));
        else Assert.Equal(count - 1, prompt.Choose("Choose", Enumerable.Range(0, count).Select(i => i.ToString()).ToArray()));
        Assert.True(terminal.Visible);
    }

    [Fact]
    public void RegionHandlesResizeAndClearsStaleRows()
    {
        var terminal = new FakeTerminal { CursorTop = 9 };
        using var region = new Region(terminal);
        region.Draw(["title", "a", "b", "c", "d"]);
        region.Draw(["filtered", "a"]);
        Assert.Equal("", terminal.Rows[7].Trim());
        terminal.Height = 5;
        terminal.Width = 20;
        terminal.CursorTop = 4;
        region.Draw(["small", "one", "hint"]);
        Assert.Contains(terminal.Rows.Values, row => row.Trim() == "small");
    }

    [Fact]
    public void EscapeRestoresCursorAndNeverReturnsPartialSecret()
    {
        var terminal = new FakeTerminal();
        terminal.Key(ConsoleKey.A, 'a');
        terminal.Key(ConsoleKey.Escape);
        Assert.Throws<OperationCanceledException>(() => new Prompts(terminal, () => CancellationToken.None).Text("Password", secret: true));
        Assert.True(terminal.Visible);
        Assert.DoesNotContain(terminal.Rows.Values, row => row.Contains("> a"));
    }

    [Fact]
    public void WideTextAndControlCharactersAreClippedSafely()
    {
        Assert.Equal("ab", Display.Fit("abcdef", 2));
        Assert.Equal("?", Display.Fit("\u001b", 1));
        Assert.Equal(" ", Display.Fit("\u4e2d", 1));
        Assert.Equal("\u4e2d", Display.Fit("\u4e2dabc", 2));
    }

    [Theory]
    [InlineData("/group \"Office machines\"", "/group", "Office machines")]
    [InlineData("/group Office machines", "/group", "Office machines")]
    [InlineData("/remote", "/remote", null)]
    public void CommandsAcceptNamesWithoutExtraTyping(string text, string verb, string? argument) =>
        Assert.Equal((verb, argument), Application.Parse(text));

    [Fact]
    public void SlashPaletteAlsoAcceptsTypedGroupArguments()
    {
        var terminal = new FakeTerminal();
        foreach (var c in "/group \"Office machines\"") terminal.Key(ConsoleKey.A, c);
        terminal.Key(ConsoleKey.Enter);
        Assert.Equal("/group \"Office machines\"", new Prompts(terminal, () => CancellationToken.None).Command());
    }
}
