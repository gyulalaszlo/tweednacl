#!/usr/bin/rdmd
import std.stdio;
import std.string;
import std.array;
import std.algorithm;
import std.range;

struct ByteInfo {
  string name;
  string startLabel;
  string endLabel;
  size_t display = 3;
}

string drawBytes( ByteInfo[] bytes, bool addComments=false )
{
  string[5] lines;
  auto o = appender!string;
  auto idx = 0;
  auto charPos = 0;

  if (addComments)
    foreach(ref l;lines) l = "// ";

  void addBlock(string center)
  {
    const len = center.length + 3;
    const border = leftJustify("+", len, '-');
    lines[1] ~= border;
    lines[2] ~= leftJustify( format("| %s", center ), len);
    lines[3] ~= border;
    charPos += len;
  }
  foreach(b;bytes) {
    charPos = 0;
    const startIdx = idx;
    foreach(i;0..b.display) {
      addBlock( format("%s", i) );
    }

    if (b.endLabel != "") {
      addBlock( "..." );
      addBlock( b.endLabel );
    }

    lines[0] ~= leftJustify( format("| %s", b.name), charPos);
    lines[4] ~= leftJustify( format("| %s", b.startLabel), charPos);
  }
  // cap it off
  lines[1] ~= "+";
  lines[2] ~= "|";
  lines[3] ~= "+";
  return join(lines[], "\n");
}

int main(string[] args)
{
  import std.getopt;
  import std.conv;
  import std.path;
  ByteInfo[] blocks;
  bool displayHeader = true;
  bool addComments = true;
  string title = "";
  getopt(
      args,
      "header",  &displayHeader,
      "comment", &addComments,
      "title", &title,
      );

  const programName = args.front;
  args.popFront();
  if (args.empty) {
    writefln("  Use the format: <label>,<startlabel>,<endlabel>,<displayed>");
    return 10;
  }

  foreach(arg;args) {
    auto parts = split(arg, ",");
    switch(parts.length) {
      case 4:
        blocks ~= ByteInfo(parts[0], parts[1], parts[2], to!size_t(parts[3]));
        break;
      case 3:
        blocks ~= ByteInfo(parts[0], parts[1], parts[2], 3);
        break;
      default:
        writefln("Cannot parse arg:%s", arg);
        writefln("  Use the format: <label>,<startlabel>,<endlabel>,<displayed>");
        return 10;
    }
  }

  if (displayHeader)
    writefln("// Generated with:\n// %s %s\n", baseName(programName), args.join(" ") );

  if (title != "") {
    writefln("%s%s", addComments ? "// " : "", title );
    writefln("%s%s\n", addComments ? "// " : "", leftJustify("", title.length, '=') );
  }
  if (addComments) writeln("---");
  writeln(drawBytes( blocks, addComments ));
  if (addComments) writeln("---");

  return 0;
}
