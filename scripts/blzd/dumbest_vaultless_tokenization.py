import random
import string
from dataclasses import dataclass, field
from typing import Dict, List


class SBox:
    """
    Represents an S-box (substitution box) mapping for a given alphabet.
    Provides an invert() method to obtain the inverse S-box.
    """

    def __init__(self, mapping: Dict[str, str]):
        self._mapping = dict(mapping)

    def __getitem__(self, key: str) -> str:
        return self._mapping[key]

    def __contains__(self, key: str) -> bool:
        return key in self._mapping

    def keys(self):
        return self._mapping.keys()

    def values(self):
        return self._mapping.values()

    def items(self):
        return self._mapping.items()

    def invert(self) -> "SBox":
        """
        Returns the inverse S-box.

        >>> sbox = SBox({'a': 'b', 'b': 'c', 'c': 'a'})
        >>> inv = sbox.invert()
        >>> inv['b']
        'a'
        >>> inv['c']
        'b'
        >>> inv['a']
        'c'
        """
        return SBox({v: k for k, v in self._mapping.items()})

    def __repr__(self):
        return f"SBox({self._mapping!r})"


class SBoxGenerator:
    """
    Utility class for generating S-boxes (substitution boxes)
    for a given alphabet and seed.
    """

    @staticmethod
    def gen_sbox(alphabet: str, seed: int) -> SBox:
        """
        Generate a secret S-box for the given alphabet using the given seed.

        >>> sbox = SBoxGenerator.gen_sbox("abc", 42)
        >>> sorted(sbox.keys())
        ['a', 'b', 'c']
        >>> set(sbox.values()) == set("abc")
        True
        """
        rnd = random.Random(seed)
        items = list(alphabet)
        rnd.shuffle(items)
        mapping = {orig: sub for orig, sub in zip(alphabet, items)}
        return SBox(mapping)


@dataclass(frozen=True)
class Domains:
    """
    Utility class for defining domain-specific alphabets and S-boxes.
    """

    DIGITS = string.digits
    UPPER = string.ascii_uppercase
    LOWER = string.ascii_lowercase
    LETTERS = string.ascii_letters


# Build S-boxes (keep these tables secret in prod!)
# — Seeds must be secret and fixed
DIGIT_SBOX = SBoxGenerator.gen_sbox(Domains.DIGITS, seed=0xC0FFEE1)
INV_DIGIT_SBX = DIGIT_SBOX.invert()

UPPER_SBOX = SBoxGenerator.gen_sbox(Domains.UPPER, seed=0xDEAD10CC)
INV_UPPER_SBX = UPPER_SBOX.invert()

LOWER_SBOX = SBoxGenerator.gen_sbox(Domains.LOWER, seed=0xF00DBABE)
INV_LOWER_SBX = LOWER_SBOX.invert()


@dataclass(frozen=True)
class CreditCardNumber:
    """
    Represents a (possibly tokenized) credit card number.
    Provides methods to tokenize and detokenize using the digit S-box.
    """

    value: str

    def tokenize(self) -> "TokenizedCreditCardNumber":
        """
        Tokenize this credit card number using the digit S-box.

        >>> cc = CreditCardNumber("4111-1111-1111-1111")
        >>> t = cc.tokenize()
        >>> isinstance(t, TokenizedCreditCardNumber)
        True
        """
        tokenized = "".join(
            DIGIT_SBOX[ch] if ch in DIGIT_SBOX else ch for ch in self.value
        )
        return TokenizedCreditCardNumber(tokenized)

    @staticmethod
    def detokenize(tokenized: "TokenizedCreditCardNumber") -> "CreditCardNumber":
        """
        Detokenize a tokenized credit card number.

        >>> cc = CreditCardNumber("4111-1111-1111-1111")
        >>> t = cc.tokenize()
        >>> CreditCardNumber.detokenize(t)
        CreditCardNumber(value='4111-1111-1111-1111')
        """
        detok = "".join(
            INV_DIGIT_SBX[ch] if ch in INV_DIGIT_SBX else ch for ch in tokenized.value
        )
        return CreditCardNumber(detok)


@dataclass(frozen=True)
class TokenizedCreditCardNumber:
    """
    Represents a tokenized credit card number.
    Provides a detokenize() method to recover the original.
    """

    value: str

    def detokenize(self) -> CreditCardNumber:
        """
        Detokenize this tokenized credit card number.

        >>> cc = CreditCardNumber("4111-1111-1111-1111")
        >>> t = cc.tokenize()
        >>> t.detokenize()
        CreditCardNumber(value='4111-1111-1111-1111')
        """
        return CreditCardNumber.detokenize(self)


@dataclass(frozen=True)
class Name:
    """
    Represents a (possibly tokenized) name.
    Provides methods to tokenize and detokenize using the letter S-boxes.
    """

    value: str

    def tokenize(self) -> "TokenizedName":
        """
        Tokenize this name using the upper/lower S-boxes.

        >>> n = Name("Alice O'Connor-Smith")
        >>> t = n.tokenize()
        >>> isinstance(t, TokenizedName)
        True
        """
        out = []
        for ch in self.value:
            if ch in Domains.UPPER:
                out.append(UPPER_SBOX[ch])
            elif ch in Domains.LOWER:
                out.append(LOWER_SBOX[ch])
            else:
                out.append(ch)
        return TokenizedName("".join(out))

    @staticmethod
    def detokenize(tokenized: "TokenizedName") -> "Name":
        """
        Detokenize a tokenized name.

        >>> n = Name("Alice O'Connor-Smith")
        >>> t = n.tokenize()
        >>> Name.detokenize(t)
        Name(value="Alice O'Connor-Smith")
        """
        out = []
        for ch in tokenized.value:
            if ch in INV_UPPER_SBX:
                out.append(INV_UPPER_SBX[ch])
            elif ch in INV_LOWER_SBX:
                out.append(INV_LOWER_SBX[ch])
            else:
                out.append(ch)
        return Name("".join(out))


@dataclass(frozen=True)
class TokenizedName:
    """
    Represents a tokenized name.
    Provides a detokenize() method to recover the original.
    """

    value: str

    def detokenize(self) -> Name:
        """
        Detokenize this tokenized name.

        >>> n = Name("Alice O'Connor-Smith")
        >>> t = n.tokenize()
        >>> t.detokenize()
        Name(value="Alice O'Connor-Smith")
        """
        return Name.detokenize(self)


@dataclass
class DigitStringSPN:
    """
    Represents a (possibly tokenized) digit string using the SPN block cipher.
    Provides methods to tokenize and detokenize.
    """

    value: str

    # Fixed parameters for the SPN (could be instance variables if needed per object)
    _BLOCK_SIZE: int = 6
    _NUM_ROUNDS: int = 4
    _PERMUTATION: List[int] = field(default_factory=lambda: [0, 3, 1, 4, 2, 5])
    _INV_PERMUTATION: List[int] = field(default_factory=lambda: [0, 2, 4, 1, 3, 5])

    def _apply_substitution_layer(self, block: str, sbox: SBox) -> str:
        """Applies the S-box substitution to each digit in the block."""
        return "".join(sbox[ch] if ch in sbox else ch for ch in block)

    def _apply_permutation_layer(self, block: str, permutation: List[int]) -> str:
        """Applies the permutation to the digits in the block."""
        if len(block) != len(permutation):
            raise ValueError("Block length must match permutation length")
        # Create a list for the result to build the permuted block
        permuted_block_list = [""] * len(block)
        for input_idx, output_idx in enumerate(permutation):
            permuted_block_list[output_idx] = block[input_idx]
        return "".join(permuted_block_list)

    def _pad_digits_pkcs7(self, data: str) -> str:
        """
        Pads the digit string using a PKCS#7-like scheme for digits.
        The padding value is the number of padding bytes (as a digit character).
        If len(data) is a multiple of block_size, a full block of padding is added.
        """
        padding_length = self._BLOCK_SIZE - (len(data) % self._BLOCK_SIZE)
        if padding_length == 0:  # Add a full block if already aligned
            padding_length = self._BLOCK_SIZE
        # Padding character is the digit representing padding_length
        padding_char = str(padding_length)
        if not padding_char.isdigit() or int(padding_char) >= 10:
            # This shouldn't happen with BLOCK_SIZE <= 9
            raise ValueError(
                f"Padding length {padding_length} results in non-digit padding char."
            )

        return data + (padding_char * padding_length)

    def _unpad_digits_pkcs7(self, data: str) -> str:
        """
        Removes PKCS#7-like padding from a digit string.
        """
        if not data:
            return ""  # Handle empty string case

        if len(data) % self._BLOCK_SIZE != 0:
            # Data length must be a multiple of block size after decryption
            raise ValueError(
                f"Data length ({len(data)}) is not a multiple of block size {self._BLOCK_SIZE}."
            )

        last_char = data[-1]
        if not last_char.isdigit():
            # Or raise an error if unexpected character is found
            raise ValueError("Padding removal failed: last character is not a digit.")

        try:
            padding_length = int(last_char)
        except ValueError:
            raise ValueError(
                "Padding removal failed: last character is not a valid digit."
            )

        # Padding length must be between 1 and BLOCK_SIZE inclusive
        if padding_length <= 0 or padding_length > self._BLOCK_SIZE:
            raise ValueError(
                f"Padding removal failed: invalid padding length {padding_length}."
            )

        # Check if the end of the string consists of padding_length copies of last_char
        if (
            len(data) >= padding_length
            and data[-padding_length:] == last_char * padding_length
        ):
            return data[:-padding_length]
        else:
            # Invalid padding sequence
            raise ValueError("Padding removal failed: invalid padding sequence.")

    def _encrypt_block(self, block: str) -> str:
        """Encrypts a single block of digits using the SPN."""
        if len(block) != self._BLOCK_SIZE:
            raise ValueError(f"Block size must be {self._BLOCK_SIZE}")

        state = block
        for _ in range(self._NUM_ROUNDS):
            # Substitution Layer
            state = self._apply_substitution_layer(state, DIGIT_SBOX)
            # Permutation Layer
            state = self._apply_permutation_layer(state, self._PERMUTATION)
        return state

    def _decrypt_block(self, block: str) -> str:
        """Decrypts a single block of digits using the inverse SPN."""
        if len(block) != self._BLOCK_SIZE:
            raise ValueError(f"Block size must be {self._BLOCK_SIZE}")

        state = block
        # Inverse rounds are applied in reverse order
        for _ in range(self._NUM_ROUNDS):
            # Inverse Permutation Layer
            state = self._apply_permutation_layer(state, self._INV_PERMUTATION)
            # Inverse Substitution Layer
            state = self._apply_substitution_layer(state, INV_DIGIT_SBX)
        return state

    def tokenize(self) -> "TokenizedDigitStringSPN":
        """
        Tokenizes the digit string using the SPN block cipher.
        Assumes the value only contains digits.
        """
        if not all(ch.isdigit() for ch in self.value):
            raise ValueError("Input string must contain only digits.")

        # Pad the input
        padded_data = self._pad_digits_pkcs7(self.value)

        tokenized_blocks = []
        # Process in blocks
        for i in range(0, len(padded_data), self._BLOCK_SIZE):
            block = padded_data[i : i + self._BLOCK_SIZE]
            tokenized_block = self._encrypt_block(block)
            tokenized_blocks.append(tokenized_block)

        return TokenizedDigitStringSPN("".join(tokenized_blocks))

    @staticmethod
    def detokenize(tokenized: "TokenizedDigitStringSPN") -> "DigitStringSPN":
        """
        Detokenizes a string tokenized by the SPN block cipher.
        Assumes input only contains digits (the substituted digits).
        """
        if not all(ch.isdigit() for ch in tokenized.value):
            # The tokenized string should also only contain digits from the SBox output
            # This check could be more specific to the SBox output alphabet if needed
            raise ValueError("Tokenized string must contain only digits.")

        # Create a temporary instance to use its methods for decryption and unpadding
        temp_instance = DigitStringSPN(value="")

        if len(tokenized.value) % temp_instance._BLOCK_SIZE != 0:
            raise ValueError(
                f"Tokenized string length ({len(tokenized.value)}) must be a multiple of block size {temp_instance._BLOCK_SIZE}."
            )

        detokenized_blocks = []
        # Process in blocks
        for i in range(0, len(tokenized.value), temp_instance._BLOCK_SIZE):
            block = tokenized.value[i : i + temp_instance._BLOCK_SIZE]
            detokenized_block = temp_instance._decrypt_block(block)
            detokenized_blocks.append(detokenized_block)

        # Unpad the result
        detokenized_padded = "".join(detokenized_blocks)
        original_data = temp_instance._unpad_digits_pkcs7(detokenized_padded)

        return DigitStringSPN(original_data)


@dataclass(frozen=True)
class TokenizedDigitStringSPN:
    """
    Represents a digit string tokenized by the SPN block cipher.
    Provides a detokenize() method to recover the original.
    """

    value: str

    def detokenize(self) -> DigitStringSPN:
        """
        Detokenize this tokenized digit string.
        """
        return DigitStringSPN.detokenize(self)


if __name__ == "__main__":
    # Using the CreditCardNumber class
    cc_plain_obj = CreditCardNumber(value="4111-1111-1111-1111")
    cc_token_obj = cc_plain_obj.tokenize()
    cc_recap_obj = cc_token_obj.detokenize()

    # Using the Name class
    name_plain_obj = Name(value="Alice O'Connor-Smith")
    name_tok_obj = name_plain_obj.tokenize()
    name_recap_obj = name_tok_obj.detokenize()

    print("CC (simple substitution) ▶", cc_plain_obj.value, "→", cc_token_obj.value)
    print("                         ↳ recover:", cc_recap_obj.value)
    print()
    print("Name (simple substitution) ▶", name_plain_obj.value, "→", name_tok_obj.value)
    print("                           ↳ recover:", name_recap_obj.value)

    print("-" * 30)
    print("SPN Digit Block Cipher Demo")

    original_digits = "4111111111111111"  # Example digit string

    try:
        # Using the new DigitStringSPN classes
        digits_plain_obj = DigitStringSPN(value=original_digits)
        digits_token_obj = digits_plain_obj.tokenize()
        digits_recap_obj = digits_token_obj.detokenize()

        print(f"\nOriginal Digits (SPN): '{digits_plain_obj.value}'")
        print(f"Tokenized (SPN):       '{digits_token_obj.value}'")
        print(f"Detokenized (SPN):     '{digits_recap_obj.value}'")

        # Verify decryption works
        assert digits_plain_obj.value == digits_recap_obj.value
        print("SPN Tokenization/Detokenization successful!")

        # Example with different length
        original_digits_short = "123"
        digits_plain_short = DigitStringSPN(value=original_digits_short)
        digits_token_short = digits_plain_short.tokenize()
        digits_recap_short = digits_token_short.detokenize()
        print(f"\nOriginal Digits (SPN): '{digits_plain_short.value}'")
        print(f"Tokenized (SPN):       '{digits_token_short.value}'")
        print(f"Detokenized (SPN):     '{digits_recap_short.value}'")
        assert digits_plain_short.value == digits_recap_short.value
        print("SPN Tokenization/Detokenization (short input) successful!")

        original_digits_exact = "123456"
        digits_plain_exact = DigitStringSPN(value=original_digits_exact)
        digits_token_exact = digits_plain_exact.tokenize()
        digits_recap_exact = digits_token_exact.detokenize()
        print(f"\nOriginal Digits (SPN): '{digits_plain_exact.value}'")
        print(f"Tokenized (SPN):       '{digits_token_exact.value}'")
        print(f"Detokenized (SPN):     '{digits_recap_exact.value}'")
        assert digits_plain_exact.value == digits_recap_exact.value
        print("SPN Tokenization/Detokenization (exact block size input) successful!")

    except ValueError as e:
        print(f"\nError during SPN demo: {e}")
