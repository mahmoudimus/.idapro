def match_pattern_with_wildcards(binary_data, pattern):
    pattern_length = len(pattern)
    binary_length = len(binary_data)

    for i in range(binary_length - pattern_length + 1):
        match = True
        for j in range(pattern_length):
            if pattern[j] != -1 and pattern[j] != binary_data[i + j]:
                match = False
                break
        if match:
            yield i  # Return the starting index of the match
    raise StopIteration
    

