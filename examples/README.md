# Digital Signatures Examples

This directory contains example scripts demonstrating how to use the digital signatures library.

## Examples

### 1. Basic Usage (`basic_usage.py`)

A comprehensive introduction to the library that covers:
- Key pair generation
- Message signing and verification
- Different data types (strings, bytes)
- Multiple hash algorithms
- Performance benchmarking

**Run with:**
```bash
uv run python examples/basic_usage.py
```

### 2. File Signing (`file_signing.py`)

Advanced example demonstrating file signing capabilities:
- Signing different file types and sizes
- Tamper detection demonstration
- Performance comparison across file sizes
- Multiple hash algorithm testing

**Run with:**
```bash
uv run python examples/file_signing.py
```

## What You'll Learn

These examples will teach you:

- **Core Concepts**: How digital signatures work with ECC
- **Practical Usage**: Real-world scenarios for signing and verification
- **Security Features**: Tamper detection and validation
- **Performance**: Understanding the performance characteristics
- **Best Practices**: Proper usage patterns and security considerations

## Expected Output

Both examples provide detailed, step-by-step output showing:
- ✅ Success indicators for each operation
- 📊 Performance metrics
- 🔍 Security demonstrations
- 📝 Signature information (lengths, validation results)

## Customization

Feel free to modify these examples to:
- Test with your own data
- Experiment with different hash algorithms
- Benchmark with your specific use cases
- Integrate with your existing codebase

## Next Steps

After running the examples:
1. Review the API documentation in the main README
2. Explore the test suite for more usage patterns
3. Consider integrating the library into your projects
4. Check the security considerations section for best practices
