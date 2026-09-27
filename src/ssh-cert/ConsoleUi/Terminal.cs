using System.Globalization;
using System.Text;

namespace SshCert.ConsoleUi;

public interface ITerminal
{
    int Width { get; }
    int Height { get; }
    int Top { get; }
    int CursorTop { get; }
    bool KeyAvailable { get; }
    ConsoleKeyInfo ReadKey();
    void Move(int column, int row);
    void Write(string value);
    ConsoleColor ForegroundColor { get; set; }
    void Cursor(bool visible);
}

public sealed class SystemTerminal : ITerminal
{
    public int Width => Console.WindowWidth;
    public int Height => Console.WindowHeight;
    public int Top => Console.WindowTop;
    public int CursorTop => Console.CursorTop;
    public bool KeyAvailable => Console.KeyAvailable;
    public ConsoleKeyInfo ReadKey() => Console.ReadKey(true);
    public void Move(int column, int row) => Console.SetCursorPosition(column, row);
    public void Write(string value) => Console.Write(value);
    public ConsoleColor ForegroundColor { get => Console.ForegroundColor; set => Console.ForegroundColor = value; }
    public void Cursor(bool visible) => Console.CursorVisible = visible;
}

public static class Display
{
    public static string Fit(string value, int columns)
    {
        var result = new StringBuilder();
        var elements = StringInfo.GetTextElementEnumerator(value);
        var used = 0;
        while (elements.MoveNext())
        {
            var element = elements.GetTextElement();
            if (element.Any(char.IsControl)) element = "?";
            var width = element.EnumerateRunes().Select(Width).DefaultIfEmpty(0).Max();
            if (used + width > columns) break;
            result.Append(element);
            used += width;
        }
        return result + new string(' ', Math.Max(0, columns - used));
    }

    private static int Width(Rune rune)
    {
        if (Rune.GetUnicodeCategory(rune) is UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark or UnicodeCategory.Format)
            return 0;
        var n = rune.Value;
        return n is >= 0x1100 and <= 0x115f or >= 0x2329 and <= 0x232a or >= 0x2e80 and <= 0xa4cf
            or >= 0xac00 and <= 0xd7a3 or >= 0xf900 and <= 0xfaff or >= 0xfe10 and <= 0xfe6f
            or >= 0xff00 and <= 0xff60 or >= 0x1f000 and <= 0x1faff or >= 0x20000 ? 2 : 1;
    }
}

public readonly record struct Viewport(int Capacity, int First, int Count)
{
    public static Viewport For(int height, int items, int selected)
    {
        var capacity = Math.Max(1, height - (height >= 8 ? 6 : 4));
        var count = Math.Min(capacity, items);
        var first = Math.Clamp(selected - capacity + 1, 0, Math.Max(0, items - count));
        return new(capacity, first, count);
    }
}

public readonly record struct DisplayLine(string Text, ConsoleColor? Color = null);

public sealed class Region(ITerminal terminal) : IDisposable
{
    private readonly ITerminal _terminal = terminal;
    private int _anchor = -1;
    private int _rows;
    private int _width;
    private int _height;
    private DisplayLine[] _previous = [];

    public void Draw(IReadOnlyList<string> lines) => Draw(lines.Select(line => new DisplayLine(line)).ToArray());

    public void Draw(IReadOnlyList<DisplayLine> lines)
    {
        var w = _terminal.Width;
        var h = _terminal.Height;
        if (w < 16 || h < 4) throw new IOException("Terminal too small. Resize to at least 16 columns and 4 rows.");
        var count = Math.Min(lines.Count, h - 1);
        if (w == _width && h == _height && _anchor >= _terminal.Top &&
            _anchor + _rows < _terminal.Top + h && _previous.SequenceEqual(lines)) return;
        if (_anchor < _terminal.Top || _anchor + _rows >= _terminal.Top + h || _width != w || _height != h || _rows < count)
        {
            _rows = count;
            _terminal.Write(new string('\n', _rows));
            _anchor = _terminal.CursorTop - _rows;
            _width = w;
            _height = h;
        }
        _terminal.Cursor(false);
        var originalColor = _terminal.ForegroundColor;
        try
        {
            for (var i = 0; i < _rows; i++)
            {
                _terminal.ForegroundColor = i < count ? lines[i].Color ?? originalColor : originalColor;
                _terminal.Move(0, _anchor + i);
                _terminal.Write(Display.Fit(i < count ? lines[i].Text : "", w - 1));
            }
        }
        finally
        {
            _terminal.ForegroundColor = originalColor;
        }
        _terminal.Move(0, _anchor + _rows);
        _previous = lines.ToArray();
    }

    public void Dispose()
    {
        _terminal.Cursor(true);
    }
}
