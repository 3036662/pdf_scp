constexpr int PowerOfTwo(int exponent) {
    return (exponent == 0) ? 1 : 2 * PowerOfTwo(exponent - 1);
}

constexpr int kMaxPdfFileSize=PowerOfTwo(9); //  2GB
