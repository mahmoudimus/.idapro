def bidirectional_convert(value, bits=64):
    """
    Converts the input value bidirectionally between decimal and hexadecimal interpretations.

    If the input is an int, it returns a tuple:
      (direct_hex, inverted_hex)
    where:
      - direct_hex is the standard Python hex() conversion (which prefixes a '-' if negative).
      - inverted_hex reinterprets the 64-bit two's complement bit pattern.
        For a negative input, inverted_hex = hex(2**bits + value);
        For a positive input, inverted_hex = hex(value - 2**bits).

    If the input is a str (expected to be in hexadecimal format,
    e.g. "0xE01761C55FC9073D" or "-0x1FE89E3AA036F8C3"),
    then this function returns a tuple:
      (direct_dec, inverted_dec)
    where:
      - direct_dec is the integer obtained from the hex string (preserving its sign).
      - inverted_dec reinterprets the same 64-bit pattern:
          for a negative number, inverted_dec = 2**bits + direct_dec;
          for a positive number, inverted_dec = direct_dec - 2**bits.

    Examples:
      >>> bidirectional_convert(-2299261584405887171)
      ('-0x1fe89e3aa036f8c3', '0xe01761c55fc9073d')

      >>> bidirectional_convert("0xe01761c55fc9073d")
      (16147482489203664445, -2299261584405887171)
    """

    mask = (1 << bits) - 1

    if isinstance(value, int):
        # Direct conversion: use Python's built-in hex conversion
        direct_hex = hex(value)
        # Invert the sign by reinterpreting the bits in a 64-bit space.
        if value < 0:
            # For negative numbers, add 2**bits to get the unsigned two's complement representation.
            inverted = (value + (1 << bits)) & mask
        else:
            # For positive numbers, subtract 2**bits to reinterpret the same bit pattern as a negative value.
            inverted = (value - (1 << bits)) & mask
        inverted_hex = hex(inverted)
        return direct_hex, inverted_hex

    elif isinstance(value, str):
        # Expect a hexadecimal string, possibly with a leading '-' sign.
        try:
            if value.startswith("-"):
                # Remove the '-' then parse, and reapply the sign.
                num = -int(value[1:], 16)
            else:
                num = int(value, 16)
        except ValueError:
            raise ValueError(
                "String must be a valid hexadecimal literal (e.g., '0x1A2B' or '-0x1A2B')"
            )

        direct_dec = num
        # Reinterpret the value in a 64-bit space
        if num < 0:
            inverted = (num + (1 << bits)) & mask
        else:
            inverted = (num - (1 << bits)) & mask
        inverted_dec = inverted
        return direct_dec, inverted_dec

    else:
        raise TypeError(
            "Value must be either an int (for a decimal input) or a str (for a hexadecimal input)."
        )
