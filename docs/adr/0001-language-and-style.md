# 0001-language-and-style.md

# ADR 0001: C++ Language Standard

## Status

Accepted

## Date

2025-11-12

## Context

We are initiating development of a mission-critical desktop application requiring robust, maintainable, and standards-compliant software. The application demands:
- Enterprise-grade reliability and long-term maintainability
- High-performance graphical user interface
- Standards-compliant development practices
- Industry-proven technology stack

After evaluating various technology options, we recognize the strategic importance of selecting technologies with strong standardization and ecosystem support.

## Decision

We have decisively chosen:

### 1. **ISO-Certified C++ as Core Programming Language**
- **Adopt C++17 ISO/IEC 14882:2017 standard** - leveraging its formal certification and international standardization
- **Benefit from 30+ years of ISO standardization** ensuring language stability and backward compatibility
- **Utilize mature ecosystem** of ISO-compliant compilers (GCC, Clang, MSVC) and tooling
- **Enterprise credibility** through ISO certification, crucial for regulated industries and long-term projects

### 2. **Google C++ Style Guide for Code Formatting**
- **Adopt Google C++ Style Guide for all formatting rules** - widely recognized as the most readable and consistent code style
- **Superior readability** through clear spacing, logical indentation, and consistent bracket placement
- **Industry-proven effectiveness** with demonstrated success in large-scale codebases (Google, numerous open-source projects)
- **Excellent tooling support** with comprehensive clang-format configurations and IDE integration
- **Reduced cognitive load** for developers through predictable, uniform code presentation

### 3. **C++ Core Guidelines for Code Quality**
- **Implement C++ Core Guidelines as our primary coding standard** - the definitive best practices for production C++ code
- **Bjarne Stroustrup and Herb Sutter endorsed** - representing collective wisdom of C++ experts
- **Production-hardened recommendations** specifically designed for real-world applications
- **Comprehensive coverage** of memory safety, resource management, and performance optimization
- **Static analysis compatibility** with tools like Clang-Tidy for automated enforcement

### 4. **Technical Implementation Standards**
- **Language Level**: C++17 ISO standard with approved features only
- **Code Formatting**: Google C++ Style Guide for all formatting and layout
- **Code Quality**: C++ Core Guidelines for architecture and best practices
- **Memory Management**: Combined RAII (C++ Core Guidelines) and smart pointers


## Consequences

### Positive

- **ISO Standardization Assurance**: C++'s ISO certification guarantees language stability, reducing technology risk
- **Optimal Readability**: Google style guide provides exceptional code clarity and maintainability
- **Production Reliability**: C++ Core Guidelines deliver battle-tested patterns for robust applications
- **Long-term Viability**: All selected technologies have decades of proven track records
- **Enterprise Credibility**: ISO certification and industry standards provide stakeholder confidence
- **Rich Ecosystem**: Access to extensive libraries, tools, and community knowledge

### Negative

- **Learning Investment**: Mastering ISO C++ standards, and comprehensive guidelines requires training
- **Style Enforcement Overhead**: Maintaining strict Google style compliance requires tooling and review processes
- **Compilation Complexity**: ISO C++ standards compliance may increase build system complexity
- **Guideline Complexity**: C++ Core Guidelines are extensive and require careful implementation

### Neutral

- Requires commitment to ongoing ISO standard updates
- Development environment setup more complex than lightweight alternatives
- Regular updates needed as Google style and Core Guidelines evolve

## Compliance

### Mandatory Standards
- All code must comply with ISO/IEC 14882:2017 (C++17) standard
- Adherence to Google C++ Style Guide formatting rules
- C++ Core Guidelines compliance for all architectural decisions
- Code reviews must verify all standards compliance

### Quality Assurance
- **clang-format** with Google style configuration for automatic formatting
- **Clang-Tidy** with C++ Core Guidelines checks for code quality
- Static analysis tools configured for ISO C++ compliance
- Cross-platform testing mandatory for all features
- Documentation must reference relevant standards and guidelines

## Notes

The selection of ISO-certified C++ provides unparalleled standards compliance and language stability, making it the optimal choice for mission-critical applications where long-term maintenance and reliability are paramount.


**Google C++ Style Guide** was selected after evaluating multiple style guides because it delivers superior readability through:
- Consistent and logical spacing that reduces visual noise
- Clear separation of code blocks and logical sections
- Industry-wide recognition and adoption
- Proven scalability in massive codebases
- Excellent tooling support that eliminates formatting debates

**C++ Core Guidelines** represent the gold standard for production C++ code because they:
- Incorporate decades of collective C++ expertise
- Focus on safety, performance, and maintainability
- Provide specific, actionable guidance for common scenarios
- Are continuously maintained by C++ standards committee members
- Have proven successful in enterprise-scale applications

This technology stack represents a conservative yet powerful approach, prioritizing standards compliance, reliability, readability, and long-term maintainability over cutting-edge but unproven alternatives.

Future considerations may include evaluating C++20 ISO standard