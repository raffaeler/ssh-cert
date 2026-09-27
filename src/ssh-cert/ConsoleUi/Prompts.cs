using SshCert.Models;

namespace SshCert.ConsoleUi;

public sealed class Prompts(ITerminal terminal, Func<CancellationToken> cancellation)
{
    private readonly ITerminal _terminal = terminal;
    private readonly Func<CancellationToken> _cancellation = cancellation;

    public static bool Interactive => !Console.IsInputRedirected && !Console.IsOutputRedirected &&
        Environment.GetEnvironmentVariable("TERM") != "dumb";

    private ConsoleKeyInfo? Key(bool cancelOnEscape = true)
    {
        _cancellation().ThrowIfCancellationRequested();
        if (!_terminal.KeyAvailable) { Thread.Sleep(35); return null; }
        var key = _terminal.ReadKey();
        if (cancelOnEscape && key.Key == ConsoleKey.Escape ||
            key.Key == ConsoleKey.C && key.Modifiers.HasFlag(ConsoleModifiers.Control))
            throw new OperationCanceledException();
        return key;
    }

    public int Choose(string title, IReadOnlyList<string> items, int initial = 0) =>
        List(title, items, false, [], initial, out _).Single();

    public HashSet<int> Check(string title, IReadOnlyList<string> items, IEnumerable<int>? selected = null,
        string emptyMessage = "(no choices available)") =>
        List(title, items, true, selected?.ToHashSet() ?? [], 0, out _, emptyMessage: emptyMessage);

    public string Command()
    {
        var text = Text("ssh-cert >", required: false, slash: true).Trim();
        if (text != "/") return text;
        string[] commands = ["/remote", "/group", "/help", "/exit"];
        var selected = List("Commands (type a command and optional group name)", commands, false, [], 0,
            out var typed, commands: true).Single();
        var parts = typed.Split(' ', 2);
        return commands[selected] + (parts.Length == 2 ? " " + parts[1] : "");
    }

    public bool Confirm(string title)
    {
        using var region = new Region(_terminal);
        while (true)
        {
            var lines = new List<DisplayLine> { new(title, ConsoleColor.Cyan) };
            if (_terminal.Height >= 6) lines.Add(new(""));
            lines.Add(new("Enter: confirm  Esc: cancel", ConsoleColor.DarkGray));
            region.Draw(lines);
            var key = Key(cancelOnEscape: false);
            if (key?.Key == ConsoleKey.Enter) return true;
            if (key?.Key == ConsoleKey.Escape) return false;
        }
    }

    private HashSet<int> List(string title, IReadOnlyList<string> items, bool multiple, HashSet<int> selected,
        int initial, out string filter, bool commands = false,
        string emptyMessage = "(no choices available)")
    {
        if (items.Count == 0 && !multiple) throw new InputException("There are no choices available.");
        filter = "";
        var cursor = Math.Clamp(initial, 0, Math.Max(0, items.Count - 1));
        using var region = new Region(_terminal);
        while (true)
        {
            var search = commands ? filter.Split(' ', 2)[0] : filter;
            var indices = Enumerable.Range(0, items.Count)
                .Where(i => items[i].Contains(search, StringComparison.OrdinalIgnoreCase)).ToList();
            cursor = Math.Clamp(cursor, 0, Math.Max(0, indices.Count - 1));
            var view = Viewport.For(_terminal.Height, indices.Count, cursor);
            var lines = new List<DisplayLine> { new(title + (filter.Length > 0 ? $" / {filter}" : ""), ConsoleColor.Cyan) };
            if (_terminal.Height >= 8) lines.Add(new(""));
            for (var i = view.First; i < view.First + view.Count; i++)
                lines.Add(new((i == cursor ? "> " : "  ") +
                    (multiple ? selected.Contains(indices[i]) ? "[X] " : "[ ] " : "") + items[indices[i]],
                    i == cursor ? ConsoleColor.Yellow : multiple && selected.Contains(indices[i]) ? ConsoleColor.Green : null));
            if (indices.Count == 0) lines.Add(new(items.Count == 0 ? emptyMessage : "(no matches)", ConsoleColor.Yellow));
            if (_terminal.Height >= 8) lines.Add(new(""));
            lines.Add(new(multiple ? "Space: toggle  Enter: confirm  Esc: cancel" : "Arrows: select  Enter: confirm  Esc: cancel", ConsoleColor.DarkGray));
            lines.Add(new((multiple ? $"{selected.Count} selected | " : "") +
                $"{indices.Count} choices | type to filter", ConsoleColor.DarkGray));
            region.Draw(lines);
            var key = Key();
            if (key is null) continue;
            switch (key.Value.Key)
            {
                case ConsoleKey.UpArrow: cursor = Math.Max(0, cursor - 1); break;
                case ConsoleKey.DownArrow: cursor = Math.Min(indices.Count - 1, cursor + 1); break;
                case ConsoleKey.Home: cursor = 0; break;
                case ConsoleKey.End: cursor = Math.Max(0, indices.Count - 1); break;
                case ConsoleKey.PageUp: cursor = Math.Max(0, cursor - view.Capacity); break;
                case ConsoleKey.PageDown: cursor = Math.Min(indices.Count - 1, cursor + view.Capacity); break;
                case ConsoleKey.Enter:
                    if (multiple) return selected;
                    if (indices.Count > 0) return [indices[cursor]];
                    break;
                case ConsoleKey.Spacebar when multiple:
                    if (indices.Count > 0 && !selected.Add(indices[cursor])) selected.Remove(indices[cursor]);
                    break;
                case ConsoleKey.Backspace:
                    if (filter.Length > 0) filter = filter[..^1];
                    cursor = 0;
                    break;
                default:
                    if (!char.IsControl(key.Value.KeyChar)) { filter += key.Value.KeyChar; cursor = 0; }
                    break;
            }
        }
    }

    public string Text(string title, string initial = "", bool secret = false, bool required = true, bool slash = false)
    {
        var text = initial;
        var cursor = text.Length;
        using var region = new Region(_terminal);
        while (true)
        {
            var shown = (secret ? new string('*', text.Length) : text).Insert(cursor, "|");
            var capacity = Math.Max(1, _terminal.Width - 5);
            var start = Math.Max(0, cursor - capacity);
            var lines = new List<DisplayLine> { new(title, ConsoleColor.Cyan) };
            if (_terminal.Height >= 6) lines.Add(new(""));
            lines.Add(new("> " + shown[start..], ConsoleColor.Yellow));
            lines.Add(new("Enter: confirm  Esc: cancel", ConsoleColor.DarkGray));
            region.Draw(lines);
            var key = Key();
            if (key is null) continue;
            switch (key.Value.Key)
            {
                case ConsoleKey.Enter:
                    if (!required || !string.IsNullOrWhiteSpace(text)) return text;
                    break;
                case ConsoleKey.Backspace:
                    if (cursor > 0) { text = text.Remove(cursor - 1, 1); cursor--; }
                    break;
                case ConsoleKey.Delete:
                    if (cursor < text.Length) text = text.Remove(cursor, 1);
                    break;
                case ConsoleKey.LeftArrow: cursor = Math.Max(0, cursor - 1); break;
                case ConsoleKey.RightArrow: cursor = Math.Min(text.Length, cursor + 1); break;
                case ConsoleKey.Home: cursor = 0; break;
                case ConsoleKey.End: cursor = text.Length; break;
                default:
                    if (slash && text.Length == 0 && key.Value.KeyChar == '/') return "/";
                    if (!char.IsControl(key.Value.KeyChar)) { text = text.Insert(cursor, key.Value.KeyChar.ToString()); cursor++; }
                    break;
            }
        }
    }

    public string Passphrase(bool creating = false)
    {
        if (!creating) return Text("Private-key passphrase (empty if none)", secret: true, required: false);
        if (!Check("Key protection", ["Protect the private key with a passphrase"]).Contains(0)) return "";
        var passphrase = Text("New private-key passphrase", secret: true);
        if (passphrase != Text("Repeat private-key passphrase", secret: true))
            throw new InputException("Passphrases did not match.");
        return passphrase;
    }
}
