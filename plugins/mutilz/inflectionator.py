"""
copied the inflection library to avoid dependency on a package. 
All rights to Janne Vanhala (@jvanhala) who ported the ruby on rails inflector to python.
"""

import re
import typing
import unicodedata

RegexReplaceList = typing.List[typing.Tuple[str, str]]

PLURALS: RegexReplaceList = [
    (r"(?i)(quiz)$", r"\1zes"),
    (r"(?i)^(oxen)$", r"\1"),
    (r"(?i)^(ox)$", r"\1en"),
    (r"(?i)(m|l)ice$", r"\1ice"),
    (r"(?i)(m|l)ouse$", r"\1ice"),
    (r"(?i)(passer)s?by$", r"\1sby"),
    (r"(?i)(matr|vert|ind)(?:ix|ex)$", r"\1ices"),
    (r"(?i)(x|ch|ss|sh)$", r"\1es"),
    (r"(?i)([^aeiouy]|qu)y$", r"\1ies"),
    (r"(?i)(hive)$", r"\1s"),
    (r"(?i)([lr])f$", r"\1ves"),
    (r"(?i)([^f])fe$", r"\1ves"),
    (r"(?i)sis$", "ses"),
    (r"(?i)([ti])a$", r"\1a"),
    (r"(?i)([ti])um$", r"\1a"),
    (r"(?i)(buffal|potat|tomat)o$", r"\1oes"),
    (r"(?i)(bu)s$", r"\1ses"),
    (r"(?i)(alias|status)$", r"\1es"),
    (r"(?i)(octop|vir)i$", r"\1i"),
    (r"(?i)(octop|vir)us$", r"\1i"),
    (r"(?i)^(ax|test)is$", r"\1es"),
    (r"(?i)s$", "s"),
    (r"$", "s"),
]

SINGULARS: RegexReplaceList = [
    (r"(?i)(database)s$", r"\1"),
    (r"(?i)(quiz)zes$", r"\1"),
    (r"(?i)(matr)ices$", r"\1ix"),
    (r"(?i)(vert|ind)ices$", r"\1ex"),
    (r"(?i)(passer)sby$", r"\1by"),
    (r"(?i)^(ox)en", r"\1"),
    (r"(?i)(alias|status)(es)?$", r"\1"),
    (r"(?i)(octop|vir)(us|i)$", r"\1us"),
    (r"(?i)^(a)x[ie]s$", r"\1xis"),
    (r"(?i)(cris|test)(is|es)$", r"\1is"),
    (r"(?i)(shoe)s$", r"\1"),
    (r"(?i)(o)es$", r"\1"),
    (r"(?i)(bus)(es)?$", r"\1"),
    (r"(?i)(m|l)ice$", r"\1ouse"),
    (r"(?i)(x|ch|ss|sh)es$", r"\1"),
    (r"(?i)(m)ovies$", r"\1ovie"),
    (r"(?i)(s)eries$", r"\1eries"),
    (r"(?i)([^aeiouy]|qu)ies$", r"\1y"),
    (r"(?i)([lr])ves$", r"\1f"),
    (r"(?i)(tive)s$", r"\1"),
    (r"(?i)(hive)s$", r"\1"),
    (r"(?i)([^f])ves$", r"\1fe"),
    (r"(?i)(t)he(sis|ses)$", r"\1hesis"),
    (r"(?i)(s)ynop(sis|ses)$", r"\1ynopsis"),
    (r"(?i)(p)rogno(sis|ses)$", r"\1rognosis"),
    (r"(?i)(p)arenthe(sis|ses)$", r"\1arenthesis"),
    (r"(?i)(d)iagno(sis|ses)$", r"\1iagnosis"),
    (r"(?i)(b)a(sis|ses)$", r"\1asis"),
    (r"(?i)(a)naly(sis|ses)$", r"\1nalysis"),
    (r"(?i)([ti])a$", r"\1um"),
    (r"(?i)(n)ews$", r"\1ews"),
    (r"(?i)(ss)$", r"\1"),
    (r"(?i)s$", ""),
]

UNCOUNTABLES: typing.Set[str] = {
    "equipment",
    "fish",
    "information",
    "jeans",
    "money",
    "rice",
    "series",
    "sheep",
    "species",
}


def camel_to_snake(name: str) -> str:
    """
    Convert a CamelCase name to snake_case.
    """
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def camelize(string: str, uppercase_first_letter: bool = True) -> str:
    """
    Convert strings to CamelCase.

    Examples::

        >>> camelize("device_type")
        'DeviceType'
        >>> camelize("device_type", False)
        'deviceType'

    :func:`camelize` can be thought of as a inverse of :func:`underscore`,
    although there are some cases where that does not hold::

        >>> camelize(underscore("IOError"))
        'IoError'

    :param uppercase_first_letter: if set to `True` :func:`camelize` converts
        strings to UpperCamelCase. If set to `False` :func:`camelize` produces
        lowerCamelCase. Defaults to `True`.
    """
    if uppercase_first_letter:
        return re.sub(r"(?:^|_)(.)", lambda m: m.group(1).upper(), string)
    else:
        return string[0].lower() + camelize(string)[1:]


def dasherize(word: str) -> str:
    """Replace underscores with dashes in the string.

    Example::

        >>> dasherize("puni_puni")
        'puni-puni'

    """
    return word.replace("_", "-")


def humanize(word: str) -> str:
    """
    Capitalize the first word and turn underscores into spaces and strip a
    trailing ``"_id"``, if any. Like :func:`titleize`, this is meant for
    creating pretty output.

    Examples::

        >>> humanize("employee_salary")
        'Employee salary'
        >>> humanize("author_id")
        'Author'

    """
    word = re.sub(r"_id$", "", word)
    word = word.replace("_", " ")
    word = re.sub(r"(?i)([a-z\d]*)", lambda m: m.group(1).lower(), word)
    word = re.sub(r"^\w", lambda m: m.group(0).upper(), word)
    return word


def ordinal(number: int) -> str:
    """
    Return the suffix that should be added to a number to denote the position
    in an ordered sequence such as 1st, 2nd, 3rd, 4th.

    Examples::

        >>> ordinal(1)
        'st'
        >>> ordinal(2)
        'nd'
        >>> ordinal(1002)
        'nd'
        >>> ordinal(1003)
        'rd'
        >>> ordinal(-11)
        'th'
        >>> ordinal(-1021)
        'st'

    """
    number = abs(int(number))
    if number % 100 in (11, 12, 13):
        return "th"
    else:
        return {
            1: "st",
            2: "nd",
            3: "rd",
        }.get(number % 10, "th")


def ordinalize(number: int) -> str:
    """
    Turn a number into an ordinal string used to denote the position in an
    ordered sequence such as 1st, 2nd, 3rd, 4th.

    Examples::

        >>> ordinalize(1)
        '1st'
        >>> ordinalize(2)
        '2nd'
        >>> ordinalize(1002)
        '1002nd'
        >>> ordinalize(1003)
        '1003rd'
        >>> ordinalize(-11)
        '-11th'
        >>> ordinalize(-1021)
        '-1021st'

    """
    return "{}{}".format(number, ordinal(number))


def parameterize(string: str, separator: str = "-") -> str:
    """
    Replace special characters in a string so that it may be used as part of a
    'pretty' URL.

    Example::

        >>> parameterize(u"Donald E. Knuth")
        'donald-e-knuth'

    """
    string = transliterate(string)
    # Turn unwanted chars into the separator
    string = re.sub(r"(?i)[^a-z0-9\-_]+", separator, string)
    if separator:
        re_sep = re.escape(separator)
        # No more than one of the separator in a row.
        string = re.sub(r"%s{2,}" % re_sep, separator, string)
        # Remove leading/trailing separator.
        string = re.sub(r"(?i)^{sep}|{sep}$".format(sep=re_sep), "", string)

    return string.lower()


def pluralize(word: str) -> str:
    """
    Return the plural form of a word.

    Examples::

        >>> pluralize("posts")
        'posts'
        >>> pluralize("octopus")
        'octopi'
        >>> pluralize("sheep")
        'sheep'
        >>> pluralize("CamelOctopus")
        'CamelOctopi'

    """
    if not word or word.lower() in UNCOUNTABLES:
        return word
    else:
        for rule, replacement in PLURALS:
            if re.search(rule, word):
                return re.sub(rule, replacement, word)
        return word


def singularize(word: str) -> str:
    """
    Return the singular form of a word, the reverse of :func:`pluralize`.

    Examples::

        >>> singularize("posts")
        'post'
        >>> singularize("octopi")
        'octopus'
        >>> singularize("sheep")
        'sheep'
        >>> singularize("word")
        'word'
        >>> singularize("CamelOctopi")
        'CamelOctopus'

    """
    for inflection in UNCOUNTABLES:
        if re.search(r"(?i)\b(%s)\Z" % inflection, word):
            return word

    for rule, replacement in SINGULARS:
        if re.search(rule, word):
            return re.sub(rule, replacement, word)
    return word


def tableize(word: str) -> str:
    """
    Create the name of a table like Rails does for models to table names. This
    method uses the :func:`pluralize` method on the last word in the string.

    Examples::

        >>> tableize('RawScaledScorer')
        'raw_scaled_scorers'
        >>> tableize('egg_and_ham')
        'egg_and_hams'
        >>> tableize('fancyCategory')
        'fancy_categories'
    """
    return pluralize(underscore(word))


def titleize(word: str) -> str:
    """
    Capitalize all the words and replace some characters in the string to
    create a nicer looking title. :func:`titleize` is meant for creating pretty
    output.

    Examples::

      >>> titleize("man from the boondocks")
      'Man From The Boondocks'
      >>> titleize("x-men: the last stand")
      'X Men: The Last Stand'
      >>> titleize("TheManWithoutAPast")
      'The Man Without A Past'
      >>> titleize("raiders_of_the_lost_ark")
      'Raiders Of The Lost Ark'

    """
    return re.sub(
        r"\b('?\w)",
        lambda match: match.group(1).capitalize(),
        humanize(underscore(word)).title(),
    )


def transliterate(string: str) -> str:
    """
    Replace non-ASCII characters with an ASCII approximation. If no
    approximation exists, the non-ASCII character is ignored. The string must
    be ``unicode``.

    Examples::

        >>> transliterate('älämölö')
        'alamolo'
        >>> transliterate('Ærøskøbing')
        'rskbing'

    """
    normalized = unicodedata.normalize("NFKD", string)
    return normalized.encode("ascii", "ignore").decode("ascii")


def underscore(word: str) -> str:
    """
    Make an underscored, lowercase form from the expression in the string.

    Example::

        >>> underscore("DeviceType")
        'device_type'

    As a rule of thumb you can think of :func:`underscore` as the inverse of
    :func:`camelize`, though there are cases where that does not hold::

        >>> camelize(underscore("IOError"))
        'IoError'

    """
    word = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", word)
    word = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", word)
    word = word.replace("-", "_")
    return word.lower()


def titleize_builtin(s: str) -> str:
    """
    Convert a snake_case string to title case with spaces.
    """
    return " ".join(word.capitalize() for word in s.split("_"))
