# DragonQuest Translation Tool

*dqtrad*

This tool can extract and replace text in Dragon Quest and Dragon Warrior (for the NES).

Python3 is required, but there are no other dependencies. You will also need a text editor
can handle UTF-8-encoded text, and access to a terminal (to run the python script).

## Usage

### Required Files

A `.tbl` file and a `symbols.json` file are required, matching the version of the ROM you are using.
The `.tbl` file describes the text encoding, and is a standard format used in many projects.
The `symbols.json` file is specific to `dqtrad`; it describes where the text is located in the ROM, as well as
where the tables are that point to different sections of text so that the tool can resize different entries in these tables.
These are provided for the USA version, and there is a rudimentry symbols file for the Japanese version as well (lacking table support).

Of course, a ROM is also required.

### Extract Text

To extract text from a ROM to a text file, use the `-o` flag:

```
python3 dqtrad.py dragon_warrior.nes usa-symbols.json usa-en.tbl -o hack.txt
```

You may then edit the file that is produced (`hack.txt`) and proceed to the following step.

Please note that in the USA edition, there are 214 unused bytes after the `--names--` section, potentially allowing
for expanded item, monster, and spell names.

### Export to ROM with replaced text.

To extract text from a ROM to a text file, use the `-i` flag to load the hack, and `-e` to export to a ROM:

```
python3 dqtrad.py dragon_warrior.nes usa-symbols.json usa-en.tbl -i hack.txt -e out.nes
```

Please note that an error may be encountered if space is exceeded.

### Dump ROM Hex

To dump the hex contents and decoded text of the ROM for viewing directly, use the `-d` flag:

```
python3 dqtrad.py dragon_warrior.nes usa-symbols.json usa-en.tbl -d dump.txt
```

This is likely not useful unless you are trying to create or edit a symbols file.
