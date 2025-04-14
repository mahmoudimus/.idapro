# -*- coding: utf-8 -*-
"""
Byte Pattern Regex Engine for IDA Pro

Combines adapted versions of Python's internal _sre components
(constants, parser, compiler) with a custom byte-matching engine.
Supports IDA-style byte patterns (HH, ??, ?H, H?), basic regex syntax
(*, +, ?, {}, |, (), []), and capture groups.
"""

import contextlib
import logging
import pathlib
import sys
import typing
from dataclasses import dataclass, field

# only import idapro if we're not running in ida
if not any(sys.executable.endswith(x) for x in ["ida.exe", "ida64.exe"]):
    import idapro

import ida_bytes
import ida_ida
import ida_range
import idaapi

# --- Configuration ---
LOG_LEVEL = logging.INFO  # Change to logging.DEBUG for verbose output


# Setup logging
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MAGIC = 20240517  # New magic number


class error(Exception):
    """Exception raised for invalid byte patterns."""

    def __init__(self, msg, pattern=None, pos=None):
        self.msg = msg
        self.pattern = pattern
        self.pos = pos
        message = f"{msg}"
        if pattern is not None and pos is not None:
            message += f" at position {pos}"
            # Basic line/col calculation might not be accurate for byte patterns
        super().__init__(message)


class _NamedIntConstant(int):
    def __new__(cls, value, name):
        self = super(_NamedIntConstant, cls).__new__(cls, value)
        self.name = name
        return self

    def __repr__(self):
        return self.name


def _makecodes(names):
    _opcode_lines = map(str.strip, names.strip().split("\n"))
    _names = []
    for line in _opcode_lines:
        if not line:
            continue
        name, _, _ = line.partition("#")
        name = name.strip()
        if name:
            _names.extend(name.split())

    # 'names' parameter is effectively replaced by _names now
    items = [_NamedIntConstant(i, name) for i, name in enumerate(_names)]
    _opcodes = {item.name: item for item in items}
    globals().update(_opcodes)
    return _opcodes


# =============================================================================
# == Byte Constants (Adapted from _constants.py) ==
# =============================================================================

MAX_GROUPS_ALLOWED = 100  # Max capture groups
MAX_REPEAT_COUNT = sys.maxsize  # Max repetition count
MAXREPEAT = _NamedIntConstant(MAX_REPEAT_COUNT, "MAXREPEAT")
MAXGROUPS = MAX_GROUPS_ALLOWED  # Use configured value
# --- Define new Byte-Oriented Opcodes ---
OPCODES = _makecodes(
    """
    FAILURE SUCCESS

    ANY_BYTE            # Matches one byte (??)
    ASSERT ASSERT_NOT   # Lookahead/behind (currently basic implementation)
    BRANCH              # Alternation (|)
    GROUPREF GROUPREF_EXISTS # Backreferences (\1, (?(1)...))
    IN_BYTESET          # Byte set ([...]) - Followed by compiled set
    INFO                # Optimization info block
    JUMP                # Unconditional jump
    LITERAL             # Used *within* IN_BYTESET definition ***
    LITERAL_MASK        # Matches byte/nibble (HH, ?H, H?). Args: value, mask
    MARK                # Capture group marker. Args: mark_id
    MAX_UNTIL           # For general REPEAT (greedy)
    MIN_UNTIL           # For general REPEAT (non-greedy)
    NEGATE              # Used within IN_BYTESET ([^...])
    RANGE               # Used *within* IN_BYTESET definition (0-255) ***
    REPEAT              # General repeat for subpatterns ({m,n})
    REPEAT_ONE_BYTE     # Optimization for single-byte repeats (*+?)
    MIN_REPEAT_ONE_BYTE # Optimization for non-greedy single-byte repeats (*+??)
    SUBPATTERN          # Grouping ( (...) )
"""
)

# --- Define Flags ---
SRE_FLAG_VERBOSE = 1  # Ignore whitespace and # comments
SRE_FLAG_DEBUG = 2  # Debugging output

# --- Define INFO flags ---
SRE_INFO_PREFIX = 1  # Has literal byte prefix
SRE_INFO_LITERAL = 2  # Entire pattern is literal bytes/wildcards
SRE_INFO_CHARSET = 4  # Pattern starts with byte from given set (IN_BYTESET)

# =============================================================================
# == Byte Parser (Adapted from _parser.py) ==
# =============================================================================

HEXDIGITS = frozenset("0123456789abcdefABCDEF")
SPECIAL_CHARS = "\\[{()*+^$|"  # Removed '?', '.' was already removed
REPEAT_CHARS = "*+?{"  # Keep '?' here for quantifiers
WHITESPACE = frozenset(" \t\n\r\v\f")

_REPEATCODES = frozenset(
    {OPCODES["REPEAT"], OPCODES["REPEAT_ONE_BYTE"], OPCODES["MIN_REPEAT_ONE_BYTE"]}
)  # Updated opcodes
_UNITCODES = frozenset(
    {
        OPCODES["ANY_BYTE"],
        OPCODES["RANGE"],
        OPCODES["IN_BYTESET"],
        OPCODES["LITERAL_MASK"],
    }
)  # Updated opcodes


class VerboseError(Exception):  # Used internally if VERBOSE flag changes mid-parse
    pass


class State:
    """Keeps track of state for parsing byte patterns."""

    def __init__(self):
        self.flags = 0
        self.groupdict = {}
        self.groupwidths = [None]  # group 0 (full match)
        self.lookbehindgroups = None  # Basic support, not fully implemented in engine

    @property
    def groups(self):
        return len(self.groupwidths)

    def opengroup(self, name=None):
        gid = self.groups
        self.groupwidths.append(None)
        if self.groups > MAXGROUPS:
            raise error("too many groups")
        if name is not None:
            ogid = self.groupdict.get(name, None)
            if ogid is not None:
                raise error(
                    f"redefinition of group name {name!r} as group {gid}; was group {ogid}"
                )
            self.groupdict[name] = gid
        return gid

    def closegroup(self, gid, p):
        self.groupwidths[gid] = p.getwidth()

    def checkgroup(self, gid):
        return gid < self.groups and self.groupwidths[gid] is not None

    def checklookbehindgroup(self, gid, source):
        # Basic check, engine support is limited
        if self.lookbehindgroups is not None:
            if not self.checkgroup(gid):
                raise source.error("cannot refer to an open group")
            if gid >= self.lookbehindgroups:
                raise source.error(
                    "cannot refer to group defined in the same lookbehind subpattern"
                )


class SubPattern:
    """A subpattern, in intermediate form."""

    def __init__(self, state, data=None):
        self.state = state
        self.data = data if data is not None else []
        self.width = None  # Cache for getwidth()

    def __len__(self):
        return len(self.data)

    def __delitem__(self, index):
        del self.data[index]

    def __getitem__(self, index):
        if isinstance(index, slice):
            return SubPattern(self.state, self.data[index])
        return self.data[index]

    def __setitem__(self, index, code):
        self.data[index] = code

    def insert(self, index, code):
        self.data.insert(index, code)

    def append(self, code):
        self.data.append(code)

    def getwidth(self):
        # Determine the width (min, max) for this subpattern
        if self.width is not None:
            return self.width
        lo = hi = 0
        for op, av in self.data:
            if op is OPCODES["BRANCH"]:
                i = MAXREPEAT - 1
                j = 0
                for item in av[1]:  # av is (None, [item1, item2, ...])
                    l, h = item.getwidth()
                    i = min(i, l)
                    j = max(j, h)
                lo += i
                hi += j
            elif op is OPCODES["SUBPATTERN"]:
                # av is (group, add_flags, del_flags, p)
                l, h = av[-1].getwidth()
                lo += l
                hi += h
            elif op in _REPEATCODES:
                # av is (min, max, item)
                l, h = av[2].getwidth()
                lo += l * av[0]
                hi += h * av[1]
            elif (
                op in _UNITCODES
            ):  # ANY_BYTE, LITERAL_MASK, IN_BYTESET, RANGE (within set)
                lo += 1
                hi += 1
            elif op is OPCODES["GROUPREF"]:
                # av is group index
                if self.state.checkgroup(av):
                    l, h = self.state.groupwidths[av]
                    lo += l
                    hi += h
                else:
                    # Cannot determine width of unresolved group ref
                    hi = MAXREPEAT  # Be pessimistic
            elif op is OPCODES["GROUPREF_EXISTS"]:
                # av is (condgroup, item_yes, item_no)
                l_yes, h_yes = av[1].getwidth()
                if av[2]:
                    l_no, h_no = av[2].getwidth()
                    lo += min(l_yes, l_no)
                    hi += max(h_yes, h_no)
                else:
                    lo += 0  # Can match zero times if condition false
                    hi += h_yes
            elif op is OPCODES["SUCCESS"]:
                break
            # Ignore MARK, JUMP, INFO, ASSERT* (zero width)
        # Ensure width doesn't exceed MAXREPEAT
        self.width = min(lo, MAXREPEAT), min(hi, MAXREPEAT)
        return self.width


class Tokenizer:
    """Tokenizes a byte pattern string."""

    def __init__(self, string):
        self.string = string
        self.index = 0
        self.next = None
        self.verbose = False  # Will be set based on flags later
        self.__next()  # Prime the tokenizer

    def __next(self):
        # Skip whitespace and comments in verbose mode
        if self.verbose:
            while self.index < len(self.string):
                char = self.string[self.index]
                if char in WHITESPACE:
                    self.index += 1
                    continue
                if char == "#":
                    # Skip to end of line or end of string
                    while (
                        self.index < len(self.string)
                        and self.string[self.index] != "\n"
                    ):
                        self.index += 1
                    continue  # Start skipping whitespace again
                break  # Found non-whitespace, non-comment

        # Standard mode: skip whitespace between tokens
        if not self.verbose:
            while (
                self.index < len(self.string) and self.string[self.index] in WHITESPACE
            ):
                self.index += 1

        if self.index >= len(self.string):
            self.next = None
            return

        char = self.string[self.index]
        start_index = self.index
        self.index += 1

        # Handle standard regex chars (excluding '?')
        if char in SPECIAL_CHARS or char in REPEAT_CHARS or char == ")":
            self.next = char
            return

        # Handle potential byte tokens (HH, ??, ?H, H?)
        token = char
        # Check for '?' specifically for byte tokens
        if char in HEXDIGITS or char == "?":
            if self.index < len(self.string):
                next_char = self.string[self.index]
                # Check for '?' specifically for byte tokens
                if next_char in HEXDIGITS or next_char == "?":
                    token += next_char
                    # Validate HH, ??, ?H, H? format
                    valid_byte_token = False
                    if token == "??":
                        valid_byte_token = True
                    elif token[0] == "?" and token[1] in HEXDIGITS:
                        valid_byte_token = True
                    elif token[0] in HEXDIGITS and token[1] == "?":
                        valid_byte_token = True
                    elif token[0] in HEXDIGITS and token[1] in HEXDIGITS:
                        valid_byte_token = True

                    if valid_byte_token:
                        self.index += 1
                        self.next = token
                        return
                    # else: Invalid two-char sequence, fall through to treat `char` alone

        # Handle escapes like \xHH
        if char == "\\":
            if self.index >= len(self.string):
                raise self.error("bad escape (end of pattern)")

            next_char = self.string[self.index]
            self.index += 1

            if next_char == "x":
                # Try to parse \xHH
                if (
                    self.index + 1 < len(self.string)
                    and self.string[self.index] in HEXDIGITS
                    and self.string[self.index + 1] in HEXDIGITS
                ):
                    self.next = (
                        f"\\x{self.string[self.index]}{self.string[self.index+1]}"
                    )
                    self.index += 2
                    return
                else:
                    raise self.error("incomplete escape \\x", 2)
            elif next_char == "g":  # Group reference \g<...>
                if self.match("<"):
                    name = self.getuntil(">", "group name")
                    self.next = f"\\g<{name}>"
                    return
                else:
                    raise self.error("missing <")
            elif next_char in "01234567":  # Octal escape or group ref \1 .. \77
                # Limited octal support for simplicity, or assume group ref
                # Let's prioritize group refs \1-\N
                num_str = next_char
                # Greedily consume up to 2 more digits for group ref
                if (
                    self.index < len(self.string)
                    and self.string[self.index] in "0123456789"
                ):
                    num_str += self.string[self.index]
                    self.index += 1
                    # Avoid consuming 3rd digit if it makes it invalid octal > 0o377
                    # This logic gets complex, maybe disallow octal escapes for now?
                    # Let's assume \1 to \MAXGROUPS are group refs
                try:
                    num = int(num_str)
                    if 1 <= num <= MAXGROUPS:
                        self.next = f"\\{num_str}"  # Token is the group ref string
                        return
                    else:  # Treat as octal if possible? Or error?
                        raise self.error(f"invalid group reference \\{num_str}")
                except ValueError:
                    raise self.error(f"invalid group reference \\{num_str}")

            elif (
                next_char in SPECIAL_CHARS
                or next_char in REPEAT_CHARS
                or next_char == "\\"
            ):
                # Escape special chars like \\, \[, \( etc.
                self.next = f"\\{next_char}"
                return
            else:
                # Treat as literal backslash followed by the char? Or error?
                raise self.error(f"bad escape \\{next_char}")

        # Handle '?' that wasn't part of a byte token or escape
        if char == "?":
            self.next = "?"
            return

        # If it wasn't a special char, byte token, or escape,
        # treat it as a single character token for the parser.
        # This allows characters like 'P' needed for extensions like (?P...).
        # The parser will validate if the character is allowed in the context.
        self.next = char  # Corrected: Return the character as a token
        return  # Corrected: Return the character as a token

        # REMOVED OLD ERROR BLOCK:
        # # If it wasn't a special char, byte token, or escape, it's an error
        # # Restore index for error message
        # self.index = start_index + len(token)
        # raise self.error(f"unexpected character or invalid token '{token}'")

    def match(self, char):
        if char == self.next:
            self.__next()
            return True
        return False

    def get(self):
        this = self.next
        self.__next()
        return this

    def tell(self):
        return self.index - len(self.next or "")

    def seek(self, index):
        self.index = index
        self.__next()

    def getuntil(self, terminator, name):
        # Used for group names \g<name>
        result = ""
        while True:
            c = self.next
            self.__next()
            if c is None:
                if not result:
                    raise self.error(f"missing {name}")
                raise self.error(
                    f"missing {terminator}, unterminated {name}", len(result)
                )
            if c == terminator:
                if not result:
                    raise self.error(f"missing {name}", 1)
                break
            result += c
        return result

    def error(self, msg, offset=0):
        return error(msg, self.string, self.tell() - offset)


def _class_escape(source, escape):
    """Handle escapes inside byte sets"""
    if escape.startswith("\\x") and len(escape) == 4:
        try:
            val = int(escape[2:], 16)
            return OPCODES["LITERAL"], val
        except ValueError:
            raise source.error(f"invalid hex escape {escape}", len(escape))
    elif escape == r"\\":
        return OPCODES["LITERAL"], ord("\\")
    elif (
        len(escape) == 2 and escape[1] in SPECIAL_CHARS
    ):  # Allow escaping set terminators etc.
        return OPCODES["LITERAL"], ord(escape[1])
    # Disallow \d, \w, \s etc. inside sets
    raise source.error(f"bad escape {escape} in character set", len(escape))


def _escape(source, escape, state):
    """Handle escapes outside byte sets"""
    # Handle \xHH
    if escape.startswith("\\x") and len(escape) == 4:
        try:
            val = int(escape[2:], 16)
            return OPCODES["LITERAL_MASK"], (val, 0xFF)
        except ValueError:
            raise source.error(f"invalid hex escape {escape}", len(escape))

    # Handle \g<name>
    if escape.startswith("\\g<") and escape.endswith(">"):
        name = escape[3:-1]
        gid = state.groupdict.get(name)
        if gid is None:
            raise source.error(f"unknown group name {name!r}", len(escape))
        if not state.checkgroup(gid):
            raise source.error("cannot refer to an open group", len(escape))
        state.checklookbehindgroup(gid, source)
        return OPCODES["GROUPREF"], gid

    # Handle \1, \2, ...
    if escape.startswith("\\") and len(escape) > 1 and escape[1:].isdigit():
        group = int(escape[1:])
        if group == 0:
            raise source.error("cannot refer to group 0", len(escape))
        if group >= state.groups:
            raise source.error(f"invalid group reference {group}", len(escape))
        if not state.checkgroup(group):
            raise source.error("cannot refer to an open group", len(escape))
        state.checklookbehindgroup(group, source)
        return OPCODES["GROUPREF"], group

    # Handle escaped special chars \\, \[, \( etc.
    if escape.startswith("\\") and len(escape) == 2:
        char = escape[1]
        if char in SPECIAL_CHARS or char in REPEAT_CHARS or char == "\\" or char == "?":
            # Treat escaped special chars as their literal byte values
            return OPCODES["LITERAL_MASK"], (ord(char), 0xFF)

    # Remove other character escapes (\n, \t, \d, \w, \s etc.)
    raise source.error(f"bad escape {escape}", len(escape))


# --- Need a new helper function _simple_tuple ---
def _simple_tuple(item_tuple):
    """Check if an item tuple represents a simple single-byte match."""
    op, av = item_tuple
    if op is OPCODES["SUBPATTERN"]:
        # Check non-capturing group with no flag changes containing a simple item
        group, add_flags, del_flags, sub_p = av
        # We need to check the *content* of sub_p (which is a SubPattern)
        return (
            group is None and not add_flags and not del_flags and _simple(sub_p)
        )  # Use original _simple here
    # Check if the *single* opcode is a basic unit
    return op in (OPCODES["LITERAL_MASK"], OPCODES["ANY_BYTE"], OPCODES["IN_BYTESET"])


def _parse_sub(source, state, verbose, nested):
    """Parse an alternation: A|B|C"""
    items = []
    itemsappend = items.append
    sourcematch = source.match
    start = source.tell()

    while True:
        itemsappend(_parse(source, state, verbose, nested + 1))
        if not sourcematch("|"):
            break

    if len(items) == 1:
        return items[0]

    subpattern = SubPattern(state)

    # Optimization: Check if all items share a common literal prefix
    # (More complex prefix optimization removed for simplicity)

    # Optimization: Check if the branch can be replaced by a character set IN_BYTESET
    set_items = []
    can_optimize_to_set = True
    for item in items:
        if len(item) == 1:
            op, av = item[0]
            if (
                op is OPCODES["LITERAL_MASK"] and av[1] == 0xFF
            ):  # Only optimize full bytes
                set_items.append((OPCODES["LITERAL"], av[0]))
            elif (
                op is OPCODES["IN_BYTESET"] and av[0][0] is not OPCODES["NEGATE"]
            ):  # Only non-negated sets
                # Ensure only LITERAL/RANGE inside
                valid_inner = True
                for set_op, set_av in av:
                    if set_op not in (OPCODES["LITERAL"], OPCODES["RANGE"]):
                        valid_inner = False
                        break
                if valid_inner:
                    set_items.extend(av)
                else:
                    can_optimize_to_set = False
                    break
            else:
                can_optimize_to_set = False
                break
        else:
            can_optimize_to_set = False
            break

    if can_optimize_to_set:
        # We can store this as a character set instead of a branch
        # Note: _uniq needs careful implementation for list of tuples
        # For simplicity, let compiler handle optimization later if needed
        # subpattern.append((IN_BYTESET, _uniq(set_items)))
        # Let's just keep it as a branch for now
        subpattern.append((OPCODES["BRANCH"], (None, items)))
    else:
        subpattern.append((OPCODES["BRANCH"], (None, items)))

    return subpattern


def _parse(source, state, verbose, nested):
    """Parse a sequence of items"""
    subpattern = SubPattern(state)
    subpatternappend = subpattern.append
    sourceget = source.get
    sourcematch = source.match

    while True:
        this = source.next
        if this is None or this in "|)":
            break  # end of pattern or subpattern

        start_pos = source.tell()  # Position before getting the token
        sourceget()  # Consume the token

        # Handle verbose mode comments/whitespace handled by tokenizer now

        if this[0] == "\\":
            code = _escape(source, this, state)
            subpatternappend(code)
        elif this in REPEAT_CHARS:
            # Repeat previous item (*, +, ?, {m,n})
            here = source.tell()
            if this == "?":
                min, max = 0, 1
            elif this == "*":
                min, max = 0, MAXREPEAT
            elif this == "+":
                min, max = 1, MAXREPEAT
            elif this == "{":
                # Parse {m,n}, {m,}, {,n}, {m}
                if source.next == "}":  # Treat {} as literal
                    subpatternappend((OPCODES["LITERAL_MASK"], (ord("{"), 0xFF)))
                    subpatternappend((OPCODES["LITERAL_MASK"], (ord("}"), 0xFF)))
                    continue
                min, max = 0, MAXREPEAT
                lo = hi = ""
                while source.next in "0123456789":
                    lo += sourceget()
                if sourcematch(","):
                    while source.next in "0123456789":
                        hi += sourceget()
                else:
                    hi = lo  # {m} case

                if not sourcematch("}"):
                    # Not a valid quantifier, treat preceding chars as literals
                    source.seek(here)  # Backtrack
                    subpatternappend((OPCODES["LITERAL_MASK"], (ord("{"), 0xFF)))
                    continue  # Reprocess the digits/comma

                if lo:
                    min = int(lo)
                if hi:
                    max = int(hi)
                if min > MAXREPEAT or max > MAXREPEAT:
                    raise OverflowError("repeat count too large")
                if max < min:
                    raise source.error(
                        "min repeat greater than max repeat", source.tell() - here
                    )
            else:
                raise AssertionError(f"unsupported quantifier {this!r}")

            # Figure out which item to repeat
            # if not subpattern:
            #     raise source.error(
            #         "nothing to repeat", source.tell() - here + len(this)
            #     )

            # # Get the actual last subpattern item (tuple: opcode, args)
            # last_item_tuple = subpattern[-1]
            # op, av_last = last_item_tuple  # op code of the item to repeat

            # # Check if the item to be repeated is itself a repeat code
            # if op in _REPEATCODES:
            #     raise source.error("multiple repeat", source.tell() - here + len(this))

            # # Check if the item's opcode is allowed to be repeated
            # allowed_repeat_ops = (
            #     OPCODES["SUBPATTERN"],
            #     OPCODES["LITERAL_MASK"],
            #     OPCODES["ANY_BYTE"],
            #     OPCODES["IN_BYTESET"],
            #     OPCODES["GROUPREF"],
            # )
            # if op not in allowed_repeat_ops:
            #     # Pass the correct length for error calculation
            #     raise source.error(
            #         "nothing to repeat", source.tell() - here + len(this)
            #     )

            # # *** Corrected: Create a SubPattern object representing the single item to be repeated ***
            # # This ensures the compiler receives the expected structure.
            # item_to_repeat_subpattern = SubPattern(state, [last_item_tuple])

            # # Handle non-greedy/possessive (possessive not implemented in engine yet)
            # if sourcematch("?"):  # Non-Greedy Match
            #     if op in (
            #         OPCODES["LITERAL_MASK"],
            #         OPCODES["ANY_BYTE"],
            #         OPCODES["IN_BYTESET"],
            #     ):  # Simple cases
            #         # Replace the last item tuple with the new repeat opcode tuple
            #         subpattern[-1] = (
            #             OPCODES["MIN_REPEAT_ONE_BYTE"],
            #             (min, max, item_to_repeat_subpattern),
            #         )
            #     else:  # General case (SUBPATTERN, GROUPREF)
            #         subpattern[-1] = (
            #             OPCODES["REPEAT"],
            #             (min, max, item_to_repeat_subpattern),
            #         )  # Mark for engine?
            #         logger.warning(
            #             "Non-greedy general repeat '??' may behave greedily."
            #         )
            # # elif sourcematch("+"): # Possessive Match (NYI)
            # #     subpattern[-1] = (POSSESSIVE_REPEAT, (min, max, item_to_repeat_subpattern))
            # else:  # Greedy Match
            #     if op in (
            #         OPCODES["LITERAL_MASK"],
            #         OPCODES["ANY_BYTE"],
            #         OPCODES["IN_BYTESET"],
            #     ):  # Simple cases
            #         # Replace the last item tuple with the new repeat opcode tuple
            #         subpattern[-1] = (
            #             OPCODES["REPEAT_ONE_BYTE"],
            #             (min, max, item_to_repeat_subpattern),
            #         )
            #     else:  # General case (SUBPATTERN, GROUPREF)
            #         subpattern[-1] = (
            #             OPCODES["REPEAT"],
            #             (min, max, item_to_repeat_subpattern),
            #         )
            # Figure out which item to repeat
            if not subpattern:
                raise source.error(
                    "nothing to repeat", source.tell() - here + len(this)
                )

            # Get the actual last item added (opcode, args tuple)
            last_item_tuple = subpattern[-1]
            last_opcode, last_av = last_item_tuple

            # Check if the *opcode* of the last item is already a repeat instruction
            if last_opcode in _REPEATCODES:
                raise source.error("multiple repeat", source.tell() - here + len(this))

            # Check if the item is something that cannot be repeated
            if last_opcode in (ASSERT, ASSERT_NOT):  # Add AT if implemented
                raise source.error(
                    "nothing to repeat", source.tell() - here + len(this)
                )

            # *** Store the raw item tuple directly ***
            item_to_repeat_tuple = last_item_tuple

            # Handle non-greedy/possessive
            if sourcematch("?"):  # Non-Greedy Match
                # *** We need _simple to check the raw tuple now ***
                if _simple_tuple(item_to_repeat_tuple):
                    repeat_opcode = MIN_REPEAT_ONE_BYTE
                else:
                    repeat_opcode = REPEAT
                    logger.warning(
                        "Non-greedy general repeat '??' may behave greedily."
                    )
            # elif sourcematch("+"): # Possessive Match (NYI)
            #     repeat_opcode = POSSESSIVE_REPEAT
            else:  # Greedy Match
                if _simple_tuple(item_to_repeat_tuple):
                    repeat_opcode = REPEAT_ONE_BYTE
                else:
                    repeat_opcode = REPEAT

            # *** Replace the last item with the new repeat structure containing the raw tuple ***
            # The compiler will need to handle this raw tuple now.
            subpattern[-1] = (repeat_opcode, (min, max, item_to_repeat_tuple))
        elif this == "??":
            subpatternappend((OPCODES["ANY_BYTE"], None))
        elif (
            len(this) == 2
            and (this[0] in HEXDIGITS or this[0] == "?")
            and (this[1] in HEXDIGITS or this[1] == "?")
        ):
            # Handle HH, ?H, H?
            h, l = this[0], this[1]
            if h == "?":
                val, mask = int(l, 16), 0x0F
            elif l == "?":
                val, mask = int(h, 16) << 4, 0xF0
            else:
                val, mask = int(this, 16), 0xFF
            subpatternappend((OPCODES["LITERAL_MASK"], (val, mask)))
        elif this == "[":
            # --- Byte Set Parsing ---
            here = source.tell() - 1
            set_content = []
            setappend = set_content.append
            negate = sourcematch("^")  # Consume ^ if present

            # *** Start: New internal loop for set parsing ***
            while True:
                # Manually peek and consume tokens for set elements
                item_token = source.next
                if item_token is None:
                    raise source.error("unterminated byte set", source.tell() - here)
                if item_token == "]":
                    if not set_content:  # Prevent empty set like [] or [^]
                        raise source.error("empty byte set", source.tell() - here)
                    source.get()  # Consume the ']'
                    break  # End of set

                source.get()  # Consume the token for the set item

                # Parse items inside set: HH, \xHH, range HH-HH
                if item_token[0] == "\\":
                    # Use _class_escape, which expects the escape sequence token
                    code1 = _class_escape(source, item_token)  # Returns (LITERAL, val)
                elif (
                    len(item_token) == 2
                    and item_token[0] in HEXDIGITS
                    and item_token[1] in HEXDIGITS
                ):
                    code1 = LITERAL, int(item_token, 16)
                # Allow escaping of '-'? e.g. [\-] ?
                # elif item_token == '\\-'?
                else:
                    # Allow literal hyphen only if it's the first char (after optional ^) or last char
                    is_literal_hyphen = item_token == "-" and (
                        not set_content or source.next == "]"
                    )
                    if is_literal_hyphen:
                        code1 = LITERAL, ord("-")
                    else:
                        raise source.error(
                            f"invalid element in byte set: '{item_token}'",
                            len(item_token),
                        )

                # Check for range following the element
                if sourcematch("-"):  # Check if the *next* token is '-'
                    # Potential range HH-HH
                    range_end_token = source.next
                    if range_end_token is None:
                        raise source.error(
                            "unterminated byte set", source.tell() - here
                        )
                    if range_end_token == "]":  # Literal hyphen at end: [A-]
                        setappend(code1)
                        setappend((LITERAL, ord("-")))
                        # Don't break yet, let the main loop consume ']'
                    else:
                        # Consume the range end token
                        source.get()
                        if range_end_token[0] == "\\":
                            code2 = _class_escape(source, range_end_token)
                        elif (
                            len(range_end_token) == 2
                            and range_end_token[0] in HEXDIGITS
                            and range_end_token[1] in HEXDIGITS
                        ):
                            code2 = LITERAL, int(range_end_token, 16)
                        else:
                            raise source.error(
                                f"invalid range end in byte set: '{range_end_token}'",
                                len(range_end_token),
                            )

                        if code1[0] != LITERAL or code2[0] != LITERAL:
                            # Should have been caught earlier if escapes were invalid
                            raise source.error(
                                "ranges must be bytes",
                                len(item_token) + 1 + len(range_end_token),
                            )

                        lo, hi = code1[1], code2[1]
                        if hi < lo:
                            raise source.error(
                                "bad byte range",
                                len(item_token) + 1 + len(range_end_token),
                            )
                        setappend((RANGE, (lo, hi)))
                else:
                    # Not a range, just append the literal element
                    setappend(code1)
            # *** End: New internal loop for set parsing ***

            # Finished parsing set
            if negate:
                set_content.insert(0, (NEGATE, None))
            subpatternappend((IN_BYTESET, set_content))

        elif this == "(":
            # Handle groups '()', '(?:...)', '(?P<name>...)', '(?(group)...|...)'
            start = source.tell() - 1
            capture = True
            name = None
            add_flags = 0  # Flags specific to this group
            del_flags = 0

            if sourcematch("?"):
                char = sourceget()
                if char is None:
                    raise source.error("unexpected end of pattern")

                if char == "P":  # Python extensions
                    if sourcematch("<"):  # Named group (?P<name>...)
                        name = source.getuntil(">", "group name")
                        if not name.isidentifier():
                            raise source.error(
                                f"bad character in group name {name!r}", len(name) + 1
                            )
                    elif sourcematch("="):  # Named backreference (?P=name)
                        name = source.getuntil(")", "group name")
                        if not name.isidentifier():
                            raise source.error(
                                f"bad character in group name {name!r}", len(name) + 1
                            )
                        gid = state.groupdict.get(name)
                        if gid is None:
                            raise source.error(
                                f"unknown group name {name!r}", len(name) + 1
                            )
                        if not state.checkgroup(gid):
                            raise source.error(
                                "cannot refer to an open group", len(name) + 1
                            )
                        state.checklookbehindgroup(gid, source)
                        subpatternappend((OPCODES["GROUPREF"], gid))
                        continue
                    else:
                        raise source.error(f"unknown extension ?P{char}", len(char) + 2)
                elif char == ":":  # Non-capturing group (?:...)
                    capture = False
                elif char == "#":  # Comment (?#...)
                    while True:
                        if source.next is None:
                            raise source.error(
                                "missing ), unterminated comment", source.tell() - start
                            )
                        if sourceget() == ")":
                            break
                    continue
                elif char == "(":  # Conditional backreference (?(id/name)yes|no)
                    condname = source.getuntil(")", "group name")
                    if condname.isidentifier():
                        condgroup = state.groupdict.get(condname)
                        if condgroup is None:
                            raise source.error(
                                f"unknown group name {condname!r}", len(condname) + 1
                            )
                    else:
                        try:
                            condgroup = int(condname)
                        except ValueError:
                            raise source.error(
                                f"bad character in group name {condname!r}",
                                len(condname) + 1,
                            ) from None
                        if not 0 < condgroup < MAXGROUPS:
                            raise source.error(
                                f"invalid group reference {condgroup}",
                                len(condname) + 1,
                            )
                    state.checklookbehindgroup(condgroup, source)  # Basic check
                    item_yes = _parse(source, state, verbose, nested + 1)
                    item_no = None
                    if source.match("|"):
                        item_no = _parse(source, state, verbose, nested + 1)
                        if source.match("|"):
                            raise source.error(
                                "conditional backref with more than two branches"
                            )
                    if not source.match(")"):
                        raise source.error(
                            "missing ), unterminated subpattern", source.tell() - start
                        )
                    subpatternappend(
                        (OPCODES["GROUPREF_EXISTS"], (condgroup, item_yes, item_no))
                    )
                    continue
                elif char == "x":  # Verbose flag specific to this group (?x:...)
                    add_flags |= SRE_FLAG_VERBOSE
                    if not source.match(":"):
                        raise source.error("missing : after ?x")
                    capture = False  # Treat as non-capturing
                # --- Remove lookahead/lookbehind/flags for now ---
                # elif char in "=!<": ...
                # elif char in FLAGS or char == "-": ...
                else:
                    raise source.error(f"unknown extension ?{char}", len(char) + 1)

            # Parse group contents
            if capture:
                try:
                    group = state.opengroup(name)
                except error as err:
                    raise source.error(err.msg, len(name or "") + 1) from None
            else:
                group = None

            # Determine verbosity for the sub-parse
            sub_verbose = (verbose or (add_flags & SRE_FLAG_VERBOSE)) and not (
                del_flags & SRE_FLAG_VERBOSE
            )
            p = _parse_sub(source, state, sub_verbose, nested + 1)

            if not source.match(")"):
                raise source.error(
                    "missing ), unterminated subpattern", source.tell() - start
                )
            if group is not None:
                state.closegroup(group, p)
            subpatternappend((OPCODES["SUBPATTERN"], (group, add_flags, del_flags, p)))

        # --- Remove ^, $ handling ---
        # elif this == "^": subpatternappend((AT, AT_BEGINNING))
        # elif this == "$": subpatternappend((AT, AT_END))

        else:
            # Should be caught by tokenizer, but as a fallback
            raise source.error(f"unexpected token: {this}")

    # Unpack non-capturing groups without flags for optimization
    # for i in range(len(subpattern))[::-1]:
    #     op, av = subpattern[i]
    #     if op is SUBPATTERN:
    #         group, add_flags, del_flags, p = av
    #         if group is None and not add_flags and not del_flags:
    #             subpattern[i: i+1] = p.data # Replace with inner data

    return subpattern


def parse(pattern_string, flags=0, state=None):
    """Parse byte pattern string into intermediate SubPattern object."""
    source = Tokenizer(pattern_string)
    source.verbose = bool(flags & SRE_FLAG_VERBOSE)  # Set tokenizer mode

    if state is None:
        state = State()
    state.flags = flags
    # state.str = pattern_string # Keep original string?

    try:
        p = _parse_sub(source, state, bool(flags & SRE_FLAG_VERBOSE), 0)
    except VerboseError:  # Should not happen if flags are fixed
        raise error("Internal verbose flag error")  # Or re-parse

    # state.flags = fix_flags(pattern_string, state.flags) # No type flags to fix

    if source.next is not None:
        assert source.next == ")"  # Only dangling ) possible?
        raise source.error("unbalanced parenthesis")

    # if flags & SRE_FLAG_DEBUG: p.dump() # Need a dump method for SubPattern

    return p


# =============================================================================
# == Byte Compiler (Adapted from _compiler.py) ==
# =============================================================================

# --- Removed _equivalences, _ignorecase_fixes ---
# --- Removed _get_iscased ---


def _combine_flags(flags, add_flags, del_flags):
    # Simplified: only handles SRE_FLAG_VERBOSE
    return (flags | add_flags) & ~del_flags


def _compile(code, pattern, flags):
    """Internal: compile a SubPattern into byte opcodes."""
    emit = code.append
    _len = len

    for op, av in pattern.data:
        if op is OPCODES["LITERAL_MASK"]:
            emit(op)
            emit(av[0])  # value
            emit(av[1])  # mask
        elif op is OPCODES["ANY_BYTE"]:
            emit(op)
        elif op is OPCODES["IN_BYTESET"]:
            emit(op)  # IN_BYTESET opcode
            skip = _len(code)
            emit(0)  # Placeholder for skip offset
            _compile_byte_charset(av, flags, code)  # Compile the set definition
            code[skip] = _len(code) - skip  # Fill in the skip offset
        elif op in (
            OPCODES["REPEAT"],
            OPCODES["REPEAT_ONE_BYTE"],
            OPCODES["MIN_REPEAT_ONE_BYTE"],
        ):
            # av is (min_count, max_count, item_tuple)
            min_count, max_count, item_tuple = av
            # Determine specific opcode based on greediness (inferred from op)
            # and simplicity of the item tuple
            is_simple = _simple_tuple(item_tuple)  # Use _simple_tuple
            is_min_one = op == OPCODES["MIN_REPEAT_ONE_BYTE"]
            is_repeat_one = op == OPCODES["REPEAT_ONE_BYTE"]

            # *** Wrap the item_tuple in a SubPattern *before* compiling it ***
            item_subpattern = SubPattern(
                pattern.state, [item_tuple]
            )  # pattern is the parent SubPattern

            if is_simple and (is_repeat_one or is_min_one):
                emit(
                    OPCODES["MIN_REPEAT_ONE_BYTE"]
                    if is_min_one
                    else OPCODES["REPEAT_ONE_BYTE"]
                )
                skip = _len(code)
                emit(0)
                emit(min_count)
                emit(max_count)
                # *** Compile the wrapped item_subpattern ***
                _compile(code, item_subpattern, flags)
                emit(OPCODES["SUCCESS"])  # Mark end of item for engine
                code[skip] = _len(code) - skip
            else:
                # Use general REPEAT / MAX_UNTIL / MIN_UNTIL
                until_op = OPCODES["MAX_UNTIL"]  # Default to greedy
                if op == OPCODES["MIN_REPEAT_ONE_BYTE"]:
                    # until_op = OPCODES["MIN_UNTIL"] # Requires engine support
                    logger.warning(
                        "Non-greedy general repeat '??' may behave greedily."
                    )

                emit(OPCODES["REPEAT"])
                skip = _len(code)
                emit(0)
                emit(min_count)
                emit(max_count)
                # *** Compile the wrapped item_subpattern ***
                _compile(code, item_subpattern, flags)
                code[skip] = _len(code) - skip
                emit(until_op)  # Emit MAX_UNTIL or MIN_UNTIL

        elif op is OPCODES["SUBPATTERN"]:
            group, add_flags, del_flags, p = av
            if group:
                emit(OPCODES["MARK"])
                emit((group - 1) * 2)  # Start mark
            # Compile subpattern with potentially modified flags
            _compile(code, p, _combine_flags(flags, add_flags, del_flags))
            if group:
                emit(OPCODES["MARK"])
                emit((group - 1) * 2 + 1)  # End mark
        elif op is OPCODES["BRANCH"]:
            emit(op)
            tail = []  # List to store locations needing jump targets filled
            tailappend = tail.append
            # av is (None, [item1, item2, ...])
            for item in av[1]:
                skip = _len(code)
                emit(0)  # Placeholder for branch length
                _compile(code, item, flags)  # Compile this branch
                emit(OPCODES["JUMP"])  # Jump past other branches
                tailappend(_len(code))
                emit(0)  # Placeholder for jump target
                code[skip] = _len(code) - skip  # Fill branch length
            emit(OPCODES["FAILURE"])  # End of branch marker
            # Fill jump targets
            end_addr = _len(code)
            for target_addr in tail:
                code[target_addr] = end_addr - target_addr
        elif op is OPCODES["GROUPREF"]:
            emit(op)
            emit(av - 1)  # Group index (0-based)
        elif op is OPCODES["GROUPREF_EXISTS"]:
            # av is (condgroup, item_yes, item_no)
            emit(op)
            emit(av[0] - 1)  # Condition group index
            skipyes = _len(code)
            emit(0)  # Placeholder for jump if condition false
            _compile(code, av[1], flags)  # Compile 'yes' branch
            if av[2]:  # If 'no' branch exists
                emit(OPCODES["JUMP"])  # Jump past 'no' branch
                skipno = _len(code)
                emit(0)  # Placeholder for jump target
                code[skipyes] = (
                    _len(code) - skipyes + 1
                )  # Fill jump offset (+1 for JUMP)
                _compile(code, av[2], flags)  # Compile 'no' branch
                code[skipno] = _len(code) - skipno  # Fill jump target
            else:  # No 'no' branch
                code[skipyes] = (
                    _len(code) - skipyes
                )  # Fill jump offset (just past 'yes')
        elif op in (OPCODES["ASSERT"], OPCODES["ASSERT_NOT"]):
            # Basic support - assumes lookahead (dir=1) for now
            # Lookbehind needs width calculation and engine support
            direction, subp = av
            if direction != 1:
                logger.warning(
                    "Lookbehind assertion not fully supported, treating as lookahead."
                )
            emit(op)
            skip = _len(code)
            emit(0)
            emit(0)  # Lookahead offset (engine uses this)
            _compile(code, subp, flags)
            emit(OPCODES["SUCCESS"])  # Mark end of assertion pattern
            code[skip] = _len(code) - skip
        elif op in (OPCODES["SUCCESS"], OPCODES["FAILURE"]):
            emit(op)
        # --- Remove AT, CATEGORY, *_IGNORE handling ---
        else:
            raise error(f"internal: unsupported operand type {op!r}")


def _compile_byte_charset(charset, flags, code):
    """Compile the list of (LITERAL/RANGE/NEGATE, data) for IN_BYTESET."""
    emit = code.append
    for op, av in charset:
        emit(op)  # Emit NEGATE, LITERAL, or RANGE
        if op is OPCODES["LITERAL"]:
            emit(av)  # Emit the byte value
        elif op is OPCODES["RANGE"]:
            emit(av[0])
            emit(av[1])  # Emit low/high byte
        # elif op is NEGATE: pass
        else:
            raise error(f"internal: unsupported set operator {op!r}")
    emit(OPCODES["FAILURE"])  # Mark end of set definition


def _optimize_charset(charset):
    """Placeholder for byte set optimization (0-255)."""
    # Could implement bitmap optimization here if needed.
    # For now, just return the parsed list.
    return charset, False  # No case folding


def _simple(p):
    """Check if subpattern p is simple (single byte match)."""
    if len(p) != 1:
        return False
    op, av = p[0]
    if op is OPCODES["SUBPATTERN"]:
        group, add_flags, del_flags, sub_p = av
        return group is None and not add_flags and not del_flags and _simple(sub_p)
    return op in (OPCODES["LITERAL_MASK"], OPCODES["ANY_BYTE"], OPCODES["IN_BYTESET"])


def _get_literal_prefix(pattern, flags):
    """Find fixed byte prefix (LITERAL_MASK with mask FF)."""
    prefix = []
    prefix_skip = None  # Not handled yet
    got_all = False
    for op, av in pattern.data:
        if op is OPCODES["LITERAL_MASK"] and av[1] == 0xFF:
            prefix.append(av[0])
        # Basic SUBPATTERN descent (no flags considered here)
        elif op is OPCODES["SUBPATTERN"] and av[0] is None and not av[1] and not av[2]:
            prefix1, skip1, all1 = _get_literal_prefix(av[3], flags)
            prefix.extend(prefix1)
            if not all1:
                break  # Stop if subpattern wasn't all literal
        else:
            break  # Not a literal byte
    else:
        got_all = True  # Reached end of pattern data
    return prefix, prefix_skip, got_all


def _get_charset_prefix(pattern, flags):
    """Check for IN_BYTESET, LITERAL_MASK, ANY_BYTE at start."""
    if not pattern.data:
        return None
    op, av = pattern.data[0]
    # Basic SUBPATTERN descent
    if op is OPCODES["SUBPATTERN"] and av[0] is None and not av[1] and not av[2]:
        return _get_charset_prefix(av[3], flags)

    if op is OPCODES["LITERAL_MASK"]:
        # Represent as a set? Only if full byte?
        if av[1] == 0xFF:
            return [(OPCODES["LITERAL"], av[0])]
        else:
            return None  # Cannot represent nibble wildcard as simple set easily
    if op is OPCODES["ANY_BYTE"]:
        return [(OPCODES["RANGE"], (0, 255))]  # Represents any byte
    if op is OPCODES["IN_BYTESET"]:
        return av  # Return the list directly
    # Could handle BRANCH if all branches start with compatible literals/sets
    return None


def _compile_info(code, pattern, flags):
    """Compile an INFO block with width and prefix/charset info."""
    lo, hi = pattern.getwidth()
    if hi > MAXREPEAT:
        hi = MAXREPEAT  # Cap max width

    prefix = []
    charset = []
    mask = 0

    if lo > 0:  # Only add prefix/charset if pattern consumes at least one byte
        prefix, prefix_skip, got_all = _get_literal_prefix(pattern, flags)
        if prefix:
            mask = SRE_INFO_PREFIX
            if prefix_skip is None and got_all:  # prefix_skip NYI
                mask |= SRE_INFO_LITERAL
        else:
            charset = _get_charset_prefix(pattern, flags)
            if charset:
                mask |= SRE_INFO_CHARSET

    # Emit INFO block
    emit = code.append
    emit(OPCODES["INFO"])
    skip = len(code)
    emit(0)  # Placeholder for skip
    emit(mask)
    emit(lo)  # Min width
    emit(hi)  # Max width

    if mask & SRE_INFO_PREFIX:
        emit(len(prefix))  # Prefix length
        emit(len(prefix))  # Skip (basic version)
        code.extend(prefix)  # Prefix bytes
        # Overlap table NYI, add dummy zeros
        code.extend([0] * len(prefix))
    elif mask & SRE_INFO_CHARSET:
        # Optimize and compile the charset directly into the INFO block
        optimized_charset, _ = _optimize_charset(charset)
        _compile_byte_charset(optimized_charset, flags, code)

    code[skip] = len(code) - skip  # Fill INFO block length


def compile(pattern_string, flags=0):
    """Compile a byte pattern string into engine-ready format."""
    # Parse the pattern string
    p = parse(pattern_string, flags)

    # Combine flags
    flags = p.state.flags | flags

    # Compile the parsed pattern into byte opcodes
    code = []
    _compile_info(code, p, flags)  # Add INFO block
    _compile(
        code, p, flags
    )  # Compile main pattern # Corrected: Pass 'p' instead of 'p.data'
    code.append(OPCODES["SUCCESS"])  # Terminate with SUCCESS

    if flags & SRE_FLAG_DEBUG:
        logger.debug("Byte Pattern Disassembly:")
        try:
            disassemble(code)  # Call our disassembler
        except Exception as e:
            logger.error("Disassembly failed: %s", e)

    # Prepare group info
    groupindex = p.state.groupdict
    indexgroup = [None] * p.state.groups
    for k, i in groupindex.items():
        indexgroup[i] = k

    # Return compiled data for the engine
    return {
        "pattern": pattern_string,
        "flags": flags,
        "code": code,
        "num_groups": p.state.groups - 1,
        "groupindex": groupindex,
        "indexgroup": tuple(indexgroup),
    }


# =============================================================================
# == Byte Match Engine (From Previous Prototype) ==
# =============================================================================


class _ByteState:
    """Manages the overall state of a match or search attempt."""

    def __init__(self, start_ea: int, end_ea: int):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.current_ea = start_ea
        self.match_start_ea = start_ea
        self.marks: typing.List[typing.Optional[int]] = []
        self.lastindex: int = -1
        self.marks_stack: typing.List[
            typing.Tuple[typing.List[typing.Optional[int]], int]
        ] = []
        self.context_stack: typing.List["_ByteMatchContext"] = []
        self.repeat_context: typing.Optional["_ByteRepeatContext"] = None

    def reset_for_match_attempt(self, attempt_ea: int):
        """Resets state for a new match attempt starting at attempt_ea."""
        self.match_start_ea = attempt_ea
        self.current_ea = attempt_ea
        self.marks = []
        self.lastindex = -1
        self.marks_stack = []
        self.context_stack = []
        self.repeat_context = None

    def get_byte(self, ea: int) -> typing.Optional[int]:
        """Safely get a byte from IDA memory within search bounds."""
        if not (self.start_ea <= ea < self.end_ea):
            return None
        try:
            # Use get_byte for modern IDA versions
            return ida_bytes.get_byte(ea)
        except (IndexError, TypeError):  # Catch potential errors on invalid addresses
            # logger.debug("Read failed at 0x%X", ea)
            return None

    def set_mark(self, mark_nr: int, ea: int):
        """Record the start/end EA for a capture group."""
        # Mark IDs are 0=grp1_start, 1=grp1_end, 2=grp2_start, ...
        if mark_nr & 1:  # End mark
            self.lastindex = mark_nr // 2 + 1  # Group index (1-based)
        if mark_nr >= len(self.marks):
            self.marks.extend([None] * (mark_nr - len(self.marks) + 1))
        self.marks[mark_nr] = ea

    def get_marks(
        self, group_index_1_based: int
    ) -> typing.Tuple[typing.Optional[int], typing.Optional[int]]:
        """Get the start and end EA for a captured group (1-based index)."""
        if group_index_1_based <= 0:
            return None, None  # Group 0 is full match
        mark_start_idx = 2 * (group_index_1_based - 1)
        mark_end_idx = mark_start_idx + 1
        start = self.marks[mark_start_idx] if mark_start_idx < len(self.marks) else None
        end = self.marks[mark_end_idx] if mark_end_idx < len(self.marks) else None
        return start, end

    def marks_push(self):
        self.marks_stack.append((list(self.marks), self.lastindex))

    def marks_pop(self):
        if self.marks_stack:
            self.marks, self.lastindex = self.marks_stack.pop()
        else:
            logger.error("Attempted to pop from empty marks stack")

    def marks_pop_keep(self):
        if self.marks_stack:
            marks_copy, lastindex_copy = self.marks_stack[-1]
            self.marks = list(marks_copy)  # Make a copy
            self.lastindex = lastindex_copy
        else:
            logger.error("Attempted to pop_keep from empty marks stack")

    def marks_pop_discard(self):
        if self.marks_stack:
            self.marks_stack.pop()
        else:
            logger.error("Attempted to pop_discard from empty marks stack")


class _ByteMatchContext:
    """Represents the execution context for a part of the pattern."""

    def __init__(
        self,
        state: _ByteState,
        pattern_codes: typing.Sequence[int],
        code_ea: int,
        current_ea: int,
    ):
        self.state = state
        self.pattern_codes = pattern_codes
        self.code_ea = code_ea  # Index in pattern_codes
        self.current_ea = current_ea  # Address in IDA memory
        self.has_matched: typing.Optional[bool] = (
            None  # None=running, True=success, False=fail
        )

    def push_new_context(self, code_offset: int) -> "_ByteMatchContext":
        """Creates a child context and pushes it onto the state's stack."""
        child_context = _ByteMatchContext(
            self.state, self.pattern_codes, self.code_ea + code_offset, self.current_ea
        )
        self.state.context_stack.append(child_context)
        return child_context

    def peek_byte(self, offset: int = 0) -> typing.Optional[int]:
        return self.state.get_byte(self.current_ea + offset)

    def skip_bytes(self, count: int):
        self.current_ea += count

    def remaining_bytes(self) -> int:
        return max(0, self.state.end_ea - self.current_ea)

    def peek_code(self, offset: int = 0) -> int:
        idx = self.code_ea + offset
        if 0 <= idx < len(self.pattern_codes):
            return self.pattern_codes[idx]
        raise IndexError(f"Pattern code read out of bounds at index {idx}")

    def skip_code(self, count: int):
        self.code_ea += count

    def remaining_codes(self) -> int:
        return max(0, len(self.pattern_codes) - self.code_ea)


class _ByteRepeatContext(_ByteMatchContext):
    """Context specific to the REPEAT general opcode."""

    def __init__(self, context: _ByteMatchContext):
        # Inherit state, codes, start code EA from parent context where REPEAT was hit
        super().__init__(
            context.state, context.pattern_codes, context.code_ea, context.current_ea
        )
        self.count = -1  # How many repetitions completed so far
        self.previous_repeat_context = (
            context.state.repeat_context
        )  # Link to outer repeat context
        self.last_match_ea = None  # To detect zero-width matches in repeats


class ByteMatch:
    """Represents a successful match result."""

    def __init__(self, pattern: "ByteRegexPattern", state: _ByteState):
        self.re = pattern
        self.start_ea = state.match_start_ea
        self.end_ea = state.current_ea
        self.lastindex = state.lastindex  # 1-based index of last group that matched
        self.num_groups = pattern.num_groups

        # Create regs tuple: ( (match_start, match_end), (group1_start, group1_end), ... )
        regs_list = [(state.match_start_ea, state.current_ea)]
        for i in range(self.num_groups):
            start, end = state.get_marks(i + 1)  # Use 1-based index
            regs_list.append((start, end))
        self.regs = tuple(regs_list)
        self.string_repr = f"<ByteMatch start=0x{self.start_ea:X}, end=0x{self.end_ea:X}, groups={self.num_groups}>"

    def span(
        self, group: typing.Union[int, str] = 0
    ) -> typing.Tuple[typing.Optional[int], typing.Optional[int]]:
        """Return the (start, end) addresses for a matched group."""
        idx = self._get_group_index(group)
        if 0 <= idx < len(self.regs):
            s, e = self.regs[idx]
            # Return None if group didn't participate (start or end is None)
            return (s, e) if s is not None and e is not None else (None, None)
        raise IndexError("no such group")

    def start(self, group: typing.Union[int, str] = 0) -> typing.Optional[int]:
        return self.span(group)[0]

    def end(self, group: typing.Union[int, str] = 0) -> typing.Optional[int]:
        return self.span(group)[1]

    def group(self, group: typing.Union[int, str] = 0) -> typing.Optional[bytes]:
        """Return the bytes matched by a group."""
        start, end = self.span(group)
        if start is not None and end is not None:
            size = end - start
            if size < 0:
                return None
            if size == 0:
                return b""
            try:
                return ida_bytes.get_bytes(start, size)
            except Exception as e:
                logger.error(
                    f"Failed to get bytes for group {group} (0x{start:X}-0x{end:X}): {e}"
                )
                return None
        return None

    def groups(
        self, default: typing.Optional[bytes] = None
    ) -> typing.Tuple[typing.Optional[bytes], ...]:
        """Return a tuple of all subgroup bytes, from 1 up."""
        return tuple(
            self.group(i) if self.start(i) is not None else default
            for i in range(1, self.num_groups + 1)
        )

    def groupdict(
        self, default: typing.Optional[bytes] = None
    ) -> typing.Dict[str, typing.Optional[bytes]]:
        """Return a dict of named subgroup bytes."""
        if not self.re.groupindex:
            return {}
        return {
            name: self.group(name) if self.start(name) is not None else default
            for name in self.re.groupindex
        }

    def _get_group_index(self, group: typing.Union[int, str]) -> int:
        """Convert group name/index to internal 0-based index."""
        if isinstance(group, str):
            if not self.re.groupindex or group not in self.re.groupindex:
                raise IndexError(f"no such named group: {group!r}")
            return self.re.groupindex[group]  # groupindex stores 1-based index
        elif isinstance(group, int):
            if not (0 <= group <= self.num_groups):
                raise IndexError(f"no such group: {group}")
            return group  # 0 for full match, 1+ for numbered groups
        else:
            raise TypeError("group argument must be int or str")

    def __repr__(self):
        return self.string_repr

    def __str__(self):
        return self.string_repr


class _ByteOpcodeDispatcher:
    """Interprets byte-oriented opcodes using a state machine."""

    def __init__(self):
        self.dispatch_table = {
            OPCODES["SUCCESS"]: self.op_success,
            OPCODES["FAILURE"]: self.op_failure,
            OPCODES["ANY_BYTE"]: self.op_any_byte,
            OPCODES["LITERAL_MASK"]: self.op_literal_mask,
            OPCODES["IN_BYTESET"]: self.op_in_byteset,
            OPCODES["JUMP"]: self.op_jump,
            OPCODES["BRANCH"]: self.op_branch,
            OPCODES["MARK"]: self.op_mark,
            OPCODES["GROUPREF"]: self.op_groupref,
            OPCODES["GROUPREF_EXISTS"]: self.op_groupref_exists,
            OPCODES["REPEAT_ONE_BYTE"]: self.op_repeat_one_byte,
            OPCODES["MIN_REPEAT_ONE_BYTE"]: self.op_min_repeat_one_byte,
            OPCODES["REPEAT"]: self.op_repeat,
            OPCODES["MAX_UNTIL"]: self.op_max_until,
            OPCODES["MIN_UNTIL"]: self.op_min_until,
            OPCODES["ASSERT"]: self.op_assert,
            OPCODES["ASSERT_NOT"]: self.op_assert_not,
            OPCODES["INFO"]: self.op_info,  # Skip INFO block during matching
            # NEGATE, RANGE are handled within IN_BYTESET
        }
        self.executing_generators = {}  # For yield-based backtracking

    def match_loop(
        self, state: _ByteState, pattern_codes: typing.Sequence[int]
    ) -> bool:
        """Main loop to drive the matching process."""
        start_code_ea = 0
        if pattern_codes and pattern_codes[0] == OPCODES["INFO"]:
            info_skip = pattern_codes[1]
            start_code_ea = info_skip + 1  # Start execution *after* the INFO block

        # Push the initial context
        initial_context = _ByteMatchContext(
            state, pattern_codes, start_code_ea, state.current_ea
        )
        state.context_stack.append(initial_context)
        # Overall result, determined *only* by the initial context's final state
        overall_match_result: typing.Optional[bool] = None

        while state.context_stack:
            context = state.context_stack[-1]
            context_id = id(context)

            # --- Resume generator if one exists ---
            generator = self.executing_generators.get(context_id)
            if generator:
                try:
                    finished = next(generator)
                    if not finished:
                        continue  # Generator yielded False, process new context
                    del self.executing_generators[context_id]  # Generator finished
                except StopIteration:
                    del self.executing_generators[context_id]  # Generator finished
                except Exception as e:
                    logger.exception(
                        f"Error resuming generator for context {context_id}: {e}"
                    )
                    context.has_matched = False  # Mark as failed on error
                    if context_id in self.executing_generators:
                        del self.executing_generators[context_id]

            # --- Execute next opcode if context is still running ---
            if context.has_matched is None:
                # Check if context ran out of codes unexpectedly (should end with SUCCESS/FAILURE)
                if context.code_ea >= len(pattern_codes):  # Check against total length
                    logger.error(
                        f"Context {context_id} ran past end of codes without SUCCESS/FAILURE"
                    )
                    context.has_matched = False  # Treat as failure

                if context.has_matched is None:  # Re-check after boundary check
                    opcode = context.peek_code()
                    method = self.dispatch_table.get(opcode, self.unknown_opcode)
                    # logger.debug(f"Ctx {context_id} EA=0x{context.current_ea:X} CodeEA={context.code_ea} Op={OPCODES[opcode]}")

                    result = method(context)  # Execute the opcode handler

                    # --- Handle generators returned by handlers ---
                    if hasattr(result, "__next__"):
                        try:
                            finished = next(result)
                            if not finished:
                                self.executing_generators[context_id] = result
                                continue  # Loop to process new context pushed by generator
                        except StopIteration:
                            pass  # Generator finished immediately
                        except Exception as e:
                            logger.exception(
                                f"Error starting generator for context {context_id}: {e}"
                            )
                            context.has_matched = False
                            if context_id in self.executing_generators:
                                del self.executing_generators[context_id]
                    # --- End generator handling ---
                # --- End opcode execution ---

            # --- Context finished processing (has_matched is True or False) ---
            if context.has_matched is not None:
                finished_context = state.context_stack.pop()

                # *** Crucial Change: Only update overall result if it's the initial context finishing ***
                if finished_context is initial_context:
                    overall_match_result = finished_context.has_matched
                    # Don't break here yet, allow stack to unwind if needed (though it should be empty)

                # Propagate results (EA) to parent if successful
                elif state.context_stack:  # If there's a parent
                    parent_context = state.context_stack[-1]
                    if finished_context.has_matched:
                        # Update parent's EA to where the successful child finished
                        parent_context.current_ea = finished_context.current_ea
                    else:
                        # If child failed, parent's state doesn't change EA,
                        # but the parent's opcode handler (e.g., BRANCH, REPEAT)
                        # will now see the failure when it resumes.
                        pass
            # --- End context finished processing ---
        # --- End while state.context_stack ---

        # Return the final result determined by the initial context
        return overall_match_result is True

    # --- Opcode Implementations ---
    def op_success(self, ctx: _ByteMatchContext) -> bool:
        ctx.state.current_ea = ctx.current_ea
        ctx.has_matched = True
        return True

    def op_failure(self, ctx: _ByteMatchContext) -> bool:
        ctx.has_matched = False
        return True

    def op_info(self, ctx: _ByteMatchContext) -> bool:  # Skip INFO block
        skip = ctx.peek_code(1)
        ctx.skip_code(skip + 1)
        return True

    def op_literal_mask(self, ctx: _ByteMatchContext) -> bool:
        byte_val = ctx.peek_code(1)
        mask = ctx.peek_code(2)
        current_byte = ctx.peek_byte()
        if current_byte is None or (current_byte & mask) != (byte_val & mask):
            ctx.has_matched = False
            return True
        ctx.skip_code(3)
        ctx.skip_bytes(1)
        return True

    def op_any_byte(self, ctx: _ByteMatchContext) -> bool:
        if ctx.peek_byte() is None:
            ctx.has_matched = False
            return True
        ctx.skip_code(1)
        ctx.skip_bytes(1)
        return True

    def op_in_byteset(self, ctx: _ByteMatchContext) -> bool:
        skip = ctx.peek_code(1)
        end_code_ea = ctx.code_ea + skip
        set_code_ea = ctx.code_ea + 2  # Start of set definition
        current_byte = ctx.peek_byte()

        if current_byte is None:
            ctx.has_matched = False
            return True

        matched = False
        negated = False
        temp_code_ea = set_code_ea

        while temp_code_ea < end_code_ea:
            op = ctx.pattern_codes[temp_code_ea]
            temp_code_ea += 1
            if op == OPCODES["NEGATE"]:
                negated = True
            elif op == OPCODES["LITERAL"]:
                val = ctx.pattern_codes[temp_code_ea]
                temp_code_ea += 1
                if current_byte == val:
                    matched = True
                    break
            elif op == OPCODES["RANGE"]:
                lo = ctx.pattern_codes[temp_code_ea]
                hi = ctx.pattern_codes[temp_code_ea + 1]
                temp_code_ea += 2
                if lo <= current_byte <= hi:
                    matched = True
                    break
            elif op == OPCODES["FAILURE"]:
                break  # End of set definition
            else:
                raise error(f"Unexpected opcode {op} in IN_BYTESET")

        if (
            matched != negated
        ):  # XOR logic: match if (matched AND NOT negated) OR (NOT matched AND negated)
            ctx.skip_code(skip + 1)
            ctx.skip_bytes(1)  # Skip IN_BYTESET, skip, set def; advance byte
            return True
        else:
            ctx.has_matched = False
            return True

    def op_jump(self, ctx: _ByteMatchContext) -> bool:
        offset = ctx.peek_code(1)
        ctx.skip_code(offset + 1)
        return True

    def op_mark(self, ctx: _ByteMatchContext) -> bool:
        gid_mark = ctx.peek_code(1)
        ctx.state.set_mark(gid_mark, ctx.current_ea)
        ctx.skip_code(2)
        return True

    def op_branch(self, ctx: _ByteMatchContext) -> typing.Generator[bool, None, None]:
        ctx.state.marks_push()
        ctx.skip_code(1)  # Skip BRANCH opcode
        original_ea = ctx.current_ea  # Store EA before trying branches

        branch_offset = ctx.peek_code(0)
        while branch_offset:
            ctx.current_ea = original_ea  # Reset EA for each branch attempt
            child_context = ctx.push_new_context(1)  # Start child after offset
            yield False  # Yield to run the child context

            if child_context.has_matched:
                ctx.has_matched = True
                yield True  # Branch succeeded

            # Branch failed, restore marks and try next branch
            ctx.state.marks_pop_keep()
            ctx.skip_code(branch_offset)  # Skip the failed branch code
            branch_offset = ctx.peek_code(0)

        # All branches failed
        ctx.state.marks_pop_discard()
        ctx.has_matched = False
        yield True

    def _check_item_match(self, ctx: _ByteMatchContext, item_code_ea: int) -> bool:
        """Helper to check if the single item at item_code_ea matches at ctx.current_ea"""
        item_opcode = ctx.pattern_codes[item_code_ea]
        current_byte = ctx.peek_byte()
        if current_byte is None:
            return False

        if item_opcode == OPCODES["LITERAL_MASK"]:
            byte_val = ctx.pattern_codes[item_code_ea + 1]
            mask = ctx.pattern_codes[item_code_ea + 2]
            return (current_byte & mask) == (byte_val & mask)
        elif item_opcode == OPCODES["ANY_BYTE"]:
            return True
        elif item_opcode == OPCODES["IN_BYTESET"]:
            # Need to simulate the IN_BYTESET logic without modifying state
            skip = ctx.pattern_codes[item_code_ea + 1]
            end_set_ea = item_code_ea + skip
            set_ea = item_code_ea + 2
            matched = False
            negated = False
            while set_ea < end_set_ea:
                op = ctx.pattern_codes[set_ea]
                set_ea += 1
                if op == OPCODES["NEGATE"]:
                    negated = True
                elif op == OPCODES["LITERAL"]:
                    val = ctx.pattern_codes[set_ea]
                    set_ea += 1
                    if current_byte == val:
                        matched = True
                        break
                elif op == OPCODES["RANGE"]:
                    lo, hi = ctx.pattern_codes[set_ea], ctx.pattern_codes[set_ea + 1]
                    set_ea += 2
                    if lo <= current_byte <= hi:
                        matched = True
                        break
                elif op == OPCODES["FAILURE"]:
                    break
            return matched != negated
        else:
            logger.error(
                f"REPEAT_ONE only supports ANY_BYTE, LITERAL_MASK, IN_BYTESET items. Got {OPCODES[item_opcode]}"
            )
            return False

    def _count_repetitions(
        self, ctx: _ByteMatchContext, max_count: int, item_code_ea: int
    ) -> int:
        """Count how many times the item at item_code_ea matches"""
        count = 0
        temp_ea = ctx.current_ea
        while count < max_count or max_count == MAXREPEAT:
            # Simulate matching the item at temp_ea
            temp_ctx = _ByteMatchContext(
                ctx.state, ctx.pattern_codes, ctx.code_ea, temp_ea
            )
            if not self._check_item_match(temp_ctx, item_code_ea):
                break
            count += 1
            temp_ea += 1
            if temp_ea >= ctx.state.end_ea:
                break  # Reached boundary
        return count

    def op_repeat_one_byte(
        self, ctx: _ByteMatchContext
    ) -> typing.Generator[bool, None, None]:
        # <REPEAT_ONE_BYTE> <skip> <min> <max> item <SUCCESS> tail
        skip = ctx.peek_code(1)
        min_count = ctx.peek_code(2)
        max_count = ctx.peek_code(3)
        item_code_ea = ctx.code_ea + 4
        tail_code_ea = ctx.code_ea + skip  # Tail starts after item + SUCCESS

        # Greedily count max repetitions
        count = self._count_repetitions(ctx, max_count, item_code_ea)

        while count >= min_count:
            current_try_ea = ctx.current_ea + count  # EA *after* matching 'count' items
            ctx.state.marks_push()
            child_context = _ByteMatchContext(
                ctx.state, ctx.pattern_codes, tail_code_ea, current_try_ea
            )
            ctx.state.context_stack.append(child_context)
            yield False  # Run the tail context

            if child_context.has_matched:
                ctx.has_matched = True
                yield True  # Success

            ctx.state.marks_pop()  # Restore marks for next attempt
            count -= 1

        ctx.has_matched = False
        yield True  # Failed

    def op_min_repeat_one_byte(
        self, ctx: _ByteMatchContext
    ) -> typing.Generator[bool, None, None]:
        # <MIN_REPEAT_ONE_BYTE> <skip> <min> <max> item <SUCCESS> tail
        skip = ctx.peek_code(1)
        min_count = ctx.peek_code(2)
        max_count = ctx.peek_code(3)
        item_code_ea = ctx.code_ea + 4
        tail_code_ea = ctx.code_ea + skip

        # Ensure min_count matches first
        initial_match_count = self._count_repetitions(ctx, min_count, item_code_ea)
        if initial_match_count < min_count:
            ctx.has_matched = False
            yield True

        count = min_count
        while count <= max_count or max_count == MAXREPEAT:
            current_try_ea = ctx.current_ea + count
            if current_try_ea > ctx.state.end_ea:
                break  # Boundary check

            ctx.state.marks_push()
            child_context = _ByteMatchContext(
                ctx.state, ctx.pattern_codes, tail_code_ea, current_try_ea
            )
            ctx.state.context_stack.append(child_context)
            yield False  # Run the tail context

            if child_context.has_matched:
                ctx.has_matched = True
                yield True  # Success

            ctx.state.marks_pop()

            # Check if the *next* item matches before incrementing count
            next_item_ea = ctx.current_ea + count
            if next_item_ea >= ctx.state.end_ea:
                break  # Boundary check for next item
            temp_next_ctx = _ByteMatchContext(
                ctx.state, ctx.pattern_codes, ctx.code_ea, next_item_ea
            )
            if not self._check_item_match(temp_next_ctx, item_code_ea):
                break  # Cannot match further items

            count += 1

        ctx.has_matched = False
        yield True  # Failed

    def op_repeat(self, ctx: _ByteMatchContext) -> typing.Generator[bool, None, None]:
        # <REPEAT> <skip> <min> <max> item <UNTIL> tail
        skip = ctx.peek_code(1)
        # Create and push repeat context onto state
        repeat_ctx = _ByteRepeatContext(ctx)
        ctx.state.repeat_context = repeat_ctx
        # Start executing the UNTIL part (which handles the logic)
        # The UNTIL opcode is located at ctx.code_ea + skip
        child_context = ctx.push_new_context(skip)
        yield False  # Run the UNTIL logic

        # --- Resumed after UNTIL finished ---
        ctx.state.repeat_context = (
            repeat_ctx.previous_repeat_context
        )  # Restore outer repeat context
        ctx.has_matched = child_context.has_matched  # Result is determined by UNTIL
        yield True

    def op_max_until(
        self, ctx: _ByteMatchContext
    ) -> typing.Generator[bool, None, None]:
        # Handles logic for greedy REPEAT
        repeat_ctx = ctx.state.repeat_context
        if repeat_ctx is None:
            raise error("Internal: MAX_UNTIL without REPEAT context")

        min_count = repeat_ctx.peek_code(2)
        max_count = repeat_ctx.peek_code(3)
        item_code_ea = repeat_ctx.code_ea + 4  # Start of the item subpattern
        item_skip = repeat_ctx.peek_code(1)  # Skip of the whole REPEAT block
        tail_code_ea = ctx.code_ea + 1  # Tail starts immediately after MAX_UNTIL

        current_match_ea = ctx.current_ea  # EA where the item *finished* matching
        count = repeat_ctx.count + 1

        # logger.debug(f"MAX_UNTIL: Count={count}, Min={min_count}, Max={max_count}, EA=0x{current_match_ea:X}")

        # --- Greedy Part: Try matching the item again first ---
        if count < max_count or max_count == MAXREPEAT:
            # Avoid infinite loop on zero-width matches
            if repeat_ctx.last_match_ea == current_match_ea and count > 0:
                # logger.debug("MAX_UNTIL: Zero-width match detected, stopping repeat.")
                pass  # Don't try to match item again
            else:
                # logger.debug("MAX_UNTIL: Trying item again (count %d)", count)
                repeat_ctx.count = count  # Tentatively increment count
                repeat_ctx.last_match_ea = (
                    current_match_ea  # Record end EA before item match
                )
                ctx.state.marks_push()
                # Push context to match the item (starts at item_code_ea)
                child_context = _ByteMatchContext(
                    ctx.state, ctx.pattern_codes, item_code_ea, current_match_ea
                )
                ctx.state.context_stack.append(child_context)
                yield False  # Run the item context

                # --- Resumed after item context ---
                if child_context.has_matched:
                    # Item matched successfully, continue the MAX_UNTIL loop recursively
                    # The child context already advanced current_ea
                    # logger.debug("MAX_UNTIL: Item matched (count %d), continuing loop.", count)
                    ctx.state.marks_pop_discard()  # Keep marks from successful item match
                    # The current context (MAX_UNTIL) will be re-entered via the stack
                    yield True  # Signal success for *this* level, loop continues
                else:
                    # Item failed to match, backtrack count and try tail
                    # logger.debug("MAX_UNTIL: Item failed (count %d), backtracking.", count)
                    repeat_ctx.count = count - 1  # Revert count
                    ctx.state.marks_pop()  # Discard marks from failed item attempt
                    # Fall through to check tail with count-1

        # --- Tail Check Part: Cannot match item further OR reached max count ---
        final_count = (
            repeat_ctx.count
        )  # The count *before* the failed item attempt (or max_count)

        if final_count < min_count:
            # logger.debug("MAX_UNTIL: Failed, count %d < min_count %d", final_count, min_count)
            ctx.has_matched = False  # Not enough matches overall
            yield True

        # Try matching the tail with the current number of repetitions
        # logger.debug("MAX_UNTIL: Trying tail check (count %d) at EA 0x{current_match_ea:X}", final_count)
        ctx.state.marks_push()
        # Restore outer repeat context *before* checking tail
        ctx.state.repeat_context = repeat_ctx.previous_repeat_context
        # Push context for the tail (starts after MAX_UNTIL)
        child_context = _ByteMatchContext(
            ctx.state, ctx.pattern_codes, tail_code_ea, current_match_ea
        )
        ctx.state.context_stack.append(child_context)
        yield False  # Run the tail context

        # --- Resumed after tail context ---
        if child_context.has_matched:
            # logger.debug("MAX_UNTIL: Tail matched (count %d). Success.", final_count)
            ctx.has_matched = True  # Overall REPEAT succeeded
            ctx.state.marks_pop_discard()  # Keep marks from successful tail match
            yield True
        else:
            # Tail failed. Need to backtrack if possible (should have been handled by item check loop)
            # logger.debug("MAX_UNTIL: Tail failed (count %d). Failure.", final_count)
            ctx.state.marks_pop()  # Discard marks from failed tail attempt
            # Restore repeat context for potential outer backtracking
            ctx.state.repeat_context = repeat_ctx
            ctx.has_matched = False
            yield True

    def op_min_until(
        self, ctx: _ByteMatchContext
    ) -> typing.Generator[bool, None, None]:
        # Handles logic for non-greedy REPEAT (NYI - behaves like MAX_UNTIL for now)
        logger.warning(
            "MIN_UNTIL (non-greedy repeat) not fully implemented, behaving greedily."
        )
        yield from self.op_max_until(ctx)  # Delegate to greedy version

    def op_groupref(self, ctx: _ByteMatchContext) -> bool:
        group_idx_0_based = ctx.peek_code(1)
        start_ea, end_ea = ctx.state.get_marks(
            group_idx_0_based + 1
        )  # Use 1-based index

        if start_ea is None or end_ea is None or start_ea > end_ea:
            ctx.has_matched = False
            return True  # Group didn't match or invalid state

        length = end_ea - start_ea
        # Compare bytes one by one
        for i in range(length):
            original_byte = ctx.state.get_byte(
                start_ea + i
            )  # Get byte from original capture
            current_byte = ctx.peek_byte(i)  # Peek at current position
            if (
                original_byte is None
                or current_byte is None
                or original_byte != current_byte
            ):
                ctx.has_matched = False
                return True

        # All bytes matched
        ctx.skip_code(2)
        ctx.skip_bytes(length)
        return True

    def op_groupref_exists(self, ctx: _ByteMatchContext) -> bool:
        # <GROUPREF_EXISTS> <group_idx_0_based> <skip_if_false> yes_code <JUMP> no_code
        group_idx_0_based = ctx.peek_code(1)
        skip_if_false = ctx.peek_code(2)
        start_ea, end_ea = ctx.state.get_marks(group_idx_0_based + 1)  # 1-based index

        group_matched = (
            start_ea is not None and end_ea is not None and start_ea <= end_ea
        )

        if group_matched:
            ctx.skip_code(3)  # Skip opcode, group_idx, skip_if_false -> start yes_code
        else:
            ctx.skip_code(skip_if_false + 1)  # Jump to start of no_code (or end)
        return True

    def op_assert(self, ctx: _ByteMatchContext) -> typing.Generator[bool, None, None]:
        # <ASSERT> <skip> <lookbehind_offset> subpattern <SUCCESS>
        skip = ctx.peek_code(1)
        lookbehind_offset = ctx.peek_code(2)  # 0 for lookahead
        subpattern_code_ea = ctx.code_ea + 3

        if lookbehind_offset != 0:
            logger.warning("Lookbehind assertion not fully supported.")
            # Need engine support to rewind ctx.current_ea

        # Try matching the subpattern without consuming bytes from main context
        original_ea = ctx.current_ea
        ctx.state.marks_push()  # Save marks before assertion check

        child_context = _ByteMatchContext(
            ctx.state, ctx.pattern_codes, subpattern_code_ea, original_ea
        )
        ctx.state.context_stack.append(child_context)
        yield False  # Run the assertion subpattern

        # --- Resumed after assertion subpattern ---
        subpattern_matched = child_context.has_matched
        ctx.state.marks_pop()  # Restore marks, assertion doesn't capture permanently

        if subpattern_matched:
            ctx.skip_code(skip + 1)  # Assertion succeeded, continue after ASSERT block
        else:
            ctx.has_matched = False  # Assertion failed

        ctx.current_ea = original_ea  # Restore original EA
        yield True

    def op_assert_not(
        self, ctx: _ByteMatchContext
    ) -> typing.Generator[bool, None, None]:
        # <ASSERT_NOT> <skip> <lookbehind_offset> subpattern <SUCCESS>
        skip = ctx.peek_code(1)
        lookbehind_offset = ctx.peek_code(2)
        subpattern_code_ea = ctx.code_ea + 3

        if lookbehind_offset != 0:
            logger.warning("Lookbehind assertion not fully supported.")

        original_ea = ctx.current_ea
        ctx.state.marks_push()
        child_context = _ByteMatchContext(
            ctx.state, ctx.pattern_codes, subpattern_code_ea, original_ea
        )
        ctx.state.context_stack.append(child_context)
        yield False

        subpattern_matched = child_context.has_matched
        ctx.state.marks_pop()

        if not subpattern_matched:  # Success if subpattern *didn't* match
            ctx.skip_code(skip + 1)
        else:
            ctx.has_matched = False

        ctx.current_ea = original_ea
        yield True

    def unknown_opcode(self, ctx: _ByteMatchContext) -> bool:
        opcode = ctx.peek_code()
        op_name = str(OPCODES[opcode]) if opcode in OPCODES else "UNKNOWN"
        logger.error(
            f"Unknown opcode {opcode} ({op_name}) encountered at code index {ctx.code_ea}"
        )
        ctx.has_matched = False
        return True


# =============================================================================
# == Top-Level Pattern Class ==
# =============================================================================


class ByteRegexPattern:
    """Represents a compiled byte pattern."""

    def __init__(self, pattern: str, flags: int = 0):
        self.pattern = pattern
        self.flags = flags
        compiled_data = compile(pattern, flags)  # Use our compiler

        self.code = compiled_data["code"]
        self.num_groups = compiled_data["num_groups"]
        self.groupindex = compiled_data["groupindex"]  # name -> 1-based index
        self.indexgroup = compiled_data["indexgroup"]  # 1-based index -> name

        # Pre-create dispatcher (can be reused)
        self._dispatcher = _ByteOpcodeDispatcher()

    def search(
        self, start_ea: int, end_ea: int = idaapi.BADADDR
    ) -> typing.Optional[ByteMatch]:
        """Scan through memory looking for the first match."""
        if end_ea == idaapi.BADADDR:
            end_ea = idaapi.inf_get_max_ea()
        if start_ea >= end_ea:
            return None

        state = _ByteState(start_ea, end_ea)
        current_ea = start_ea
        min_width = 0

        # Basic optimization: check min width from INFO block if present
        if self.code and self.code[0] == OPCODES["INFO"]:
            min_width = self.code[3]  # Min width is at index 3

        while (
            current_ea <= end_ea - min_width
        ):  # Optimization: stop if remaining bytes < min_width
            state.reset_for_match_attempt(current_ea)
            if self._dispatcher.match_loop(state, self.code):
                return ByteMatch(self, state)
            current_ea += 1  # Advance search position by 1

        return None

    def finditer(
        self, start_ea: int, end_ea: int = idaapi.BADADDR
    ) -> typing.Iterator[ByteMatch]:
        """Find all non-overlapping matches."""
        if end_ea == idaapi.BADADDR:
            end_ea = idaapi.inf_get_max_ea()

        current_ea = start_ea
        while current_ea < end_ea:
            match = self.search(current_ea, end_ea)
            if match:
                yield match
                # Advance past this match
                next_ea = (
                    match.end_ea
                    if match.end_ea > match.start_ea
                    else match.start_ea + 1
                )
                if next_ea <= current_ea:  # Safety break for zero-width or errors
                    logger.warning(
                        f"Search did not advance (0x{current_ea:X} -> 0x{next_ea:X}), advancing by 1."
                    )
                    current_ea += 1
                else:
                    current_ea = next_ea
            else:
                break  # No more matches found

    def match(
        self, start_ea: int, end_ea: int = idaapi.BADADDR
    ) -> typing.Optional[ByteMatch]:
        """Check for a match only at the beginning of the search range."""
        if end_ea == idaapi.BADADDR:
            end_ea = idaapi.inf_get_max_ea()
        if start_ea >= end_ea:
            return None

        state = _ByteState(start_ea, end_ea)
        state.reset_for_match_attempt(start_ea)  # Only try at start_ea
        if self._dispatcher.match_loop(state, self.code):
            # Ensure the match started exactly at start_ea
            match_obj = ByteMatch(self, state)
            if match_obj.start_ea == start_ea:
                return match_obj
        return None


# =============================================================================
# == Disassembler (for Debugging) ==
# =============================================================================


def disassemble(code):
    """Basic disassembler for the compiled byte opcodes."""
    labels = set()
    jumps = set()

    # First pass: find jump targets
    i = 0
    while i < len(code):
        op = code[i]
        op_enum = OPCODES[op] if op < len(OPCODES) else None
        if op_enum in (
            OPCODES["JUMP"],
            OPCODES["BRANCH"],
            OPCODES["REPEAT"],
            OPCODES["REPEAT_ONE_BYTE"],
            OPCODES["MIN_REPEAT_ONE_BYTE"],
            OPCODES["ASSERT"],
            OPCODES["ASSERT_NOT"],
            OPCODES["GROUPREF_EXISTS"],
            OPCODES["INFO"],
            OPCODES["IN_BYTESET"],
        ):
            skip = code[i + 1]
            target = (
                i
                + skip
                + (1 if op_enum not in (OPCODES["INFO"], OPCODES["IN_BYTESET"]) else 0)
            )  # Adjust target based on opcode structure
            if op_enum == OPCODES["JUMP"]:
                target = i + skip + 1  # JUMP target is relative to *after* skip arg
            if op_enum == OPCODES["BRANCH"]:
                # Branch targets are relative to start of *next* branch/failure
                current = i + 1 + 1  # Start after BRANCH and first skip
                while code[current - 1] != 0:  # While skip != 0
                    branch_len = code[current - 1]
                    jumps.add(current + branch_len)  # Target of the implicit JUMP
                    current += branch_len
            elif op_enum == OPCODES["GROUPREF_EXISTS"]:
                # Target if condition false
                jumps.add(i + skip + 1)
                # Also check for implicit jump past 'no' branch if present
                # This requires deeper parsing, skip for now
            elif op_enum in (
                OPCODES["REPEAT"],
                OPCODES["REPEAT_ONE_BYTE"],
                OPCODES["MIN_REPEAT_ONE_BYTE"],
                OPCODES["ASSERT"],
                OPCODES["ASSERT_NOT"],
            ):
                jumps.add(i + skip + 1)  # Target is after the block
            elif op_enum in (OPCODES["INFO"], OPCODES["IN_BYTESET"]):
                jumps.add(i + skip + 1)  # Target is after the block
            else:  # JUMP
                jumps.add(i + skip + 1)

        # Advance i based on opcode length
        if op_enum is None:
            i += 1
            continue
        if op_enum in (
            OPCODES["SUCCESS"],
            OPCODES["FAILURE"],
            OPCODES["ANY_BYTE"],
            OPCODES["NEGATE"],
            OPCODES["MAX_UNTIL"],
            OPCODES["MIN_UNTIL"],
        ):
            i += 1
        elif op_enum in (OPCODES["LITERAL_MASK"],):
            i += 3
        elif op_enum in (OPCODES["MARK"], OPCODES["GROUPREF"], OPCODES["RANGE"]):
            i += 2
        elif op_enum in (OPCODES["JUMP"], OPCODES["ASSERT"], OPCODES["ASSERT_NOT"]):
            i += 3  # opcode, skip, arg
        elif op_enum in (
            OPCODES["REPEAT"],
            OPCODES["REPEAT_ONE_BYTE"],
            OPCODES["MIN_REPEAT_ONE_BYTE"],
        ):
            i += 4  # opcode, skip, min, max
        elif op_enum in (OPCODES["GROUPREF_EXISTS"],):
            i += 3  # opcode, group, skip
        elif op_enum in (OPCODES["INFO"], OPCODES["IN_BYTESET"], OPCODES["BRANCH"]):
            i += 2  # opcode, skip (rest handled in loop)
        else:
            i += 1  # Default advance

    # Second pass: print disassembly
    i = 0
    addr_width = len(str(len(code)))
    while i < len(code):
        addr_str = f"{i:<{addr_width}}"
        label_str = "*" if i in jumps else " "
        line = f"{label_str}{addr_str}: "

        op = code[i]
        # Handle potential unknown opcodes gracefully
        try:
            op_enum = OPCODES[op]
            op_name = str(op_enum)
        except (IndexError, KeyError):
            op_enum = None
            op_name = f"OP({op})"

        line += f"{op_name:<18}"
        i_start = i
        i += 1  # Consume opcode

        args = []
        # --- Add try-except block for safety when reading args ---
        try:
            if op_enum is None:
                pass
            elif op_enum in (SUCCESS, FAILURE, ANY_BYTE, NEGATE, MAX_UNTIL, MIN_UNTIL):
                pass
            elif op_enum is LITERAL_MASK:
                val, mask = code[i : i + 2]
                i += 2
                args.append(f"Val=0x{val:02X} Mask=0x{mask:02X}")
            elif op_enum is MARK:
                mark_id = code[i]
                i += 1
                args.append(f"MarkID={mark_id}")
            elif op_enum is GROUPREF:
                group_idx = code[i]
                i += 1
                args.append(f"Group={group_idx+1}")  # Display 1-based
            elif op_enum is RANGE:
                lo, hi = code[i : i + 2]
                i += 2
                args.append(f"Low=0x{lo:02X} High=0x{hi:02X}")
            elif op_enum is JUMP:
                skip = code[i]
                i += 1
                target = i_start + skip + 1  # Target relative to start of JUMP instr
                args.append(f"Skip={skip} (Target={target})")
            elif op_enum in (ASSERT, ASSERT_NOT):
                skip, lookbehind = code[i : i + 2]
                i += 2  # Consume skip and lookbehind
                target = i_start + skip + 1  # Target relative to start of ASSERT instr
                args.append(f"Skip={skip} Lookbehind={lookbehind} (Target={target})")
            elif op_enum in (REPEAT, REPEAT_ONE_BYTE, MIN_REPEAT_ONE_BYTE):
                skip, min_r, max_r = code[i : i + 3]
                i += 3  # Consume skip, min, max
                target = i_start + skip + 1  # Target relative to start of REPEAT instr
                max_str = "MAX" if max_r == MAXREPEAT else str(max_r)
                args.append(f"Skip={skip} Min={min_r} Max={max_str} (Target={target})")
            elif op_enum is GROUPREF_EXISTS:
                group_idx, skip = code[i : i + 2]
                i += 2
                target = (
                    i_start + skip + 1
                )  # Target relative to start of GROUPREF_EXISTS instr
                args.append(f"Group={group_idx+1} Skip={skip} (Target={target})")
            elif op_enum is INFO:
                # Read static part: skip, flags, min, max
                skip = code[i]
                i_skip_arg = i
                i += 1  # Save index of skip arg
                # --- Boundary check before reading static args ---
                if i + 2 >= len(code):
                    args.append("(Error reading INFO args!)")
                    i = i_start + skip + 1  # Try to jump to expected end
                else:
                    info_flags, min_w, max_w = code[i : i + 3]
                    i += 3
                    target = (
                        i_start + skip + 1
                    )  # Target relative to start of INFO instr
                    max_w_str = "MAX" if max_w == MAXREPEAT else str(max_w)
                    args.append(
                        f"Skip={skip} Flags={info_flags} MinW={min_w} MaxW={max_w_str} (Target={target})"
                    )

                    # --- Correctly parse variable part based on flags ---
                    info_data_start = i  # Where variable data starts
                    try:  # Add try-except around variable part parsing
                        if info_flags & SRE_INFO_PREFIX:
                            if i + 1 < len(
                                code
                            ):  # Check bounds before reading prefix_len/skip
                                prefix_len, prefix_skip_info = code[i : i + 2]
                                i += 2
                                # Check bounds before reading prefix + overlap
                                if i + (prefix_len * 2) <= len(code):
                                    # Skip prefix bytes + overlap table bytes
                                    i += prefix_len * 2
                                else:
                                    args.append("(Error reading prefix data!)")
                                    i = i_start + skip + 1  # Jump to expected end
                            else:
                                args.append("(Error reading prefix info!)")
                                i = i_start + skip + 1  # Jump to expected end
                        elif info_flags & SRE_INFO_CHARSET:
                            # Parse the charset definition to find its end (marked by FAILURE)
                            set_i = i
                            while set_i < len(code):
                                set_op = code[set_i]
                                set_i += 1
                                if set_op == LITERAL:
                                    if set_i >= len(code):
                                        raise IndexError  # Check bound
                                    set_i += 1
                                elif set_op == RANGE:
                                    if set_i + 1 >= len(code):
                                        raise IndexError  # Check bound
                                    set_i += 2
                                elif set_op == FAILURE:
                                    break
                                elif set_op == NEGATE:
                                    pass  # Just skip
                                else:  # Unexpected opcode in set
                                    args.append(f"(Error parsing charset op {set_op}!)")
                                    set_i = i_start + skip + 1  # Jump to expected end
                                    break
                            else:  # Loop finished without finding FAILURE
                                args.append("(Error: Unterminated charset in INFO!)")
                                set_i = i_start + skip + 1  # Jump to expected end
                            i = set_i  # Advance 'i' past the charset definition
                    except IndexError:
                        args.append("(Error reading INFO variable data!)")
                        i = i_start + skip + 1  # Jump to expected end

                # --- Verification and Force Alignment ---
                expected_end = i_start + skip + 1
                if i != expected_end:
                    logger.warning(
                        f"Disassembler INFO parsing mismatch: calculated end {i}, expected {expected_end}. Forcing alignment."
                    )
                    i = expected_end  # Force 'i' to the expected end

            elif op_enum is IN_BYTESET:
                skip = code[i]
                i += 1
                target = (
                    i_start + skip + 1
                )  # Target relative to start of IN_BYTESET instr
                args.append(f"Skip={skip} (Target={target})")
                # Advance 'i' past the set definition
                set_i = i
                while set_i < len(code):
                    set_op = code[set_i]
                    set_i += 1
                    if set_op == LITERAL:
                        set_i += 1
                    elif set_op == RANGE:
                        set_i += 2
                    elif set_op == FAILURE:
                        break
                    # Ignore NEGATE
                i = set_i  # Advance 'i' past the set definition
                expected_end = i_start + skip + 1
                if i != expected_end:
                    logger.warning(
                        f"Disassembler IN_BYTESET parsing mismatch: calculated end {i}, expected {expected_end}"
                    )
                    i = expected_end  # Force 'i' to the expected end

            elif op_enum is BRANCH:
                # The first skip tells us the length of the *first* branch only
                skip1 = code[i]
                i += 1
                target1 = i_start + skip1 + 1
                args.append(f"Branch1 Skip={skip1} (Target={target1})")
                # The main loop will continue processing subsequent branches/FAILURE

            else:  # Default case if arguments weren't handled
                pass

        except IndexError:
            line += " (Error reading arguments!)"
            i = i_start + 1  # Advance by at least 1 to avoid infinite loop

        line += ", ".join(args)
        logger.debug(line)

        # # Special handling to advance past complex blocks like BRANCH, INFO, IN_BYTESET body
        # if op_enum in (OPCODES["INFO"], OPCODES["IN_BYTESET"]):
        #     i = i_start + code[i_start + 1] + 1  # Jump past the block
        # elif op_enum is OPCODES["BRANCH"]:
        #     # Need to skip over all branches defined by the first skip
        #     current = i_start + 1 + 1  # After BRANCH and first skip
        #     while code[current - 1] != 0:  # While skip != 0
        #         branch_len = code[current - 1]
        #         current += branch_len
        #     i = current  # Position after the final FAILURE of the branch


# =============================================================================
# == Example Usage (IDA Pro) ==
# =============================================================================


@contextlib.contextmanager
def idapro_context(
    file_path: pathlib.Path, run_auto_analysis: bool = True, compress_db: bool = True
):
    idapro.enable_console_messages(True)
    idapro.open_database(str(file_path), run_auto_analysis)
    if run_auto_analysis:
        idaapi.auto_wait()

    yield

    print("Closing database")
    ida_ida.inf_set_compress_idb(compress_db)
    idapro.close_database()


def _example():
    # --- Example 1: Simple pattern ---
    try:
        # Find PUSH RBP; MOV RBP, RSP equivalent: 55 48 89 E5
        # Use wildcards: 55 48 ?? E5
        pattern_str = "55 48 ?? E5"
        print(f"\n--- Example 1: Searching for '{pattern_str}' ---")

        # Compile the pattern (with debug flag)
        # Use SRE_FLAG_DEBUG for disassembly output
        bp = ByteRegexPattern(pattern_str, SRE_FLAG_DEBUG)

        # Define search range (e.g., current function or segment)
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        if func:
            start_ea, end_ea = func.start_ea, func.end_ea
            print(f"Searching in function: 0x{start_ea:X} - 0x{end_ea:X}")
        else:
            seg = idaapi.get_segm_by_name(".text")  # Or other segment
            if seg:
                start_ea, end_ea = seg.start_ea, seg.end_ea
                print(f"Searching in segment: .text (0x{start_ea:X} - 0x{end_ea:X})")
            else:
                start_ea, end_ea = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
                print(f"Searching full address range: 0x{start_ea:X} - 0x{end_ea:X}")

        # Find matches
        found_count = 0
        for match in bp.finditer(start_ea, end_ea):
            print(
                f"  Match {found_count+1}: 0x{match.start_ea:X} (len={match.end_ea-match.start_ea}) Bytes: {match.group(0).hex().upper()}"
            )
            found_count += 1
            if found_count >= 10:
                print("  (Stopping after 10 matches)")
                break
        if found_count == 0:
            print("  No matches found.")

    except error as e:
        print(f"Pattern Error: {e}")
    except Exception as e:
        logger.exception("An error occurred during Example 1:")
        print(f"An unexpected error occurred: {e}")

    # --- Example 2: Pattern with Quantifiers and Groups ---
    try:
        # Find CALL/JMP instruction (E8/E9) followed by 0 to 3 NOPs (90) then RET (C3)
        # Capture the CALL/JMP target offset (relative)
        # Pattern: ([E8 E9]) ?? ?? ?? ?? (90){0,3} C3
        # Note: Capturing the offset bytes requires GROUPREF, not implemented here yet for extraction
        # Let's capture the E8/E9 byte and the C3 byte
        pattern_str = r"([E8 E9]) ?? ?? ?? ?? (?: 90 ){0,3} ( C3 )"  # Corrected: Replaced \x?? with ??
        print(f"\n--- Example 2: Searching for '{pattern_str}' ---")

        bp = ByteRegexPattern(pattern_str, SRE_FLAG_DEBUG)

        # Use same search range as Example 1
        # (Assuming start_ea, end_ea are still defined)
        if "start_ea" not in locals():
            start_ea, end_ea = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
            print(f"Searching full address range: 0x{start_ea:X} - 0x{end_ea:X}")
        else:
            print(f"Searching range: 0x{start_ea:X} - 0x{end_ea:X}")

        found_count = 0
        for match in bp.finditer(start_ea, end_ea):
            print(
                f"  Match {found_count+1}: 0x{match.start_ea:X} (len={match.end_ea-match.start_ea})"
            )
            print(f"    Full Match: {match.group(0).hex().upper()}")
            print(f"    Group 1 (CALL/JMP Opcode): {match.group(1).hex().upper()}")
            print(f"    Group 2 (RET Opcode): {match.group(2).hex().upper()}")
            found_count += 1
            if found_count >= 10:
                print("  (Stopping after 10 matches)")
                break
        if found_count == 0:
            print("  No matches found.")

    except error as e:
        print(f"Pattern Error: {e}")
    except Exception as e:
        logger.exception("An error occurred during Example 2:")
        print(f"An unexpected error occurred: {e}")

    # --- Example 3: Named Groups and Alternation ---
    try:
        # Find either MOV EAX, imm32 (B8 ....) or MOV RAX, imm64 (48 B8 ....)
        # (?P<mov32> B8 ?? ?? ?? ??) | (?P<mov64> 48 B8 ?? ?? ?? ?? ?? ?? ??)
        pattern_str = (
            r"(?P<mov32> B8 ?? ?? ?? ??) | (?P<mov64> 48 B8 ?? ?? ?? ?? ?? ?? ??)"
        )
        print(f"\n--- Example 3: Searching for '{pattern_str}' ---")

        bp = ByteRegexPattern(
            pattern_str, SRE_FLAG_DEBUG | SRE_FLAG_VERBOSE
        )  # Use verbose flag

        if "start_ea" not in locals():
            start_ea, end_ea = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
            print(f"Searching full address range: 0x{start_ea:X} - 0x{end_ea:X}")
        else:
            print(f"Searching range: 0x{start_ea:X} - 0x{end_ea:X}")

        found_count = 0
        for match in bp.finditer(start_ea, end_ea):
            print(
                f"  Match {found_count+1}: 0x{match.start_ea:X} (len={match.end_ea-match.start_ea})"
            )
            groups = match.groupdict()
            if groups.get("mov32"):
                print(f"    Type: MOV EAX, imm32 -> {groups['mov32'].hex().upper()}")
            elif groups.get("mov64"):
                print(f"    Type: MOV RAX, imm64 -> {groups['mov64'].hex().upper()}")
            else:
                print(
                    f"    Type: Unknown (Shouldn't happen) -> {match.group(0).hex().upper()}"
                )

            found_count += 1
            if found_count >= 10:
                print("  (Stopping after 10 matches)")
                break
        if found_count == 0:
            print("  No matches found.")

    except error as e:
        print(f"Pattern Error: {e}")
    except Exception as e:
        logger.exception("An error occurred during Example 3:")
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    print(OPCODES)
    with idapro_context(pathlib.Path(".").parent / "tmp/boombox.exe.i64"):
        _example()


if __name__ == "__main__":
    print(OPCODES)
    with idapro_context(pathlib.Path(".").parent / "tmp/boombox.exe.i64"):
        _example()
