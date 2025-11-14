# About

C++ code style 

# Static analysis

### Analysis tool

Use the **clang-tidy** tool for code analysis.

### Analysis settings
Settings for the **clang-tidy** tool can be found in the [.clang-tidy](.clang-tidy) file.

All checks are performed except those explicitly disabled in the settings file.

Here is the nonexhaustive (just for an instance) list of checks:

* Bug-prone
  - [bugprone-assignment-in-if-condition](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/assignment-in-if-condition.html#bugprone-assignment-in-if-condition)
  - [bugprone-bool-pointer-implicit-conversion](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/bool-pointer-implicit-conversion.html#bugprone-bool-pointer-implicit-conversion)
  - [bugprone-branch-clone](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/branch-clone.html#bugprone-branch-clone)
  - [bugprone-copy-constructor-init](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/copy-constructor-init.html#bugprone-copy-constructor-init) 
  - [bugprone-empty-catch](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/empty-catch.html#bugprone-empty-catch)
  - [bugprone-exception-escape](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/exception-escape.html#bugprone-exception-escape)  
  - [bugprone-narrowing-conversions](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/narrowing-conversions.html#bugprone-narrowing-conversions)
  - [bugprone-switch-missing-default-case](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/switch-missing-default-case.html#bugprone-switch-missing-default-case)
  - [bugprone-unchecked-optional-access](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/unchecked-optional-access.html#bugprone-unchecked-optional-access)
  - [bugprone-use-after-move](https://clang.llvm.org/extra/clang-tidy/checks/bugprone/use-after-move.html#bugprone-use-after-move)
  - ...
  
* Core guidelines:
  - [modernize-avoid-c-arrays](https://clang.llvm.org/extra/clang-tidy/checks/modernize/avoid-c-arrays.html)
  - [cppcoreguidelines-avoid-const-or-ref-data-members](https://clang.llvm.org/extra/clang-tidy/checks/cppcoreguidelines/avoid-const-or-ref-data-members.html#cppcoreguidelines-avoid-const-or-ref-data-members)
  - [cppcoreguidelines-avoid-do-while](https://clang.llvm.org/extra/clang-tidy/checks/cppcoreguidelines/avoid-do-while.html#cppcoreguidelines-avoid-do-while)
  - [cppcoreguidelines-macro-usage](https://clang.llvm.org/extra/clang-tidy/checks/cppcoreguidelines/macro-usage.html#cppcoreguidelines-macro-usage)
  - [performance-noexcept-move-constructor](https://clang.llvm.org/extra/clang-tidy/checks/performance/noexcept-move-constructor.html)
  - [cppcoreguidelines-prefer-member-initializer](https://clang.llvm.org/extra/clang-tidy/checks/cppcoreguidelines/prefer-member-initializer.html#cppcoreguidelines-prefer-member-initializer)
  - ...


# Version control

Use Git for version control.

# Links

This code style is based on:
 + [Google C++ Code Style](https://google.github.io/styleguide/cppguide.html).
 + [C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)

# C++ Version
Code should target C++17; the target version may be changed in the future.

# Header files

In general, every .cpp file should have an associated .hpp file. 
Unit tests and small .cpp files may contain just a main() function.

All header files should have guards to prevent multiple inclusion.

Prefer `#pragma once` instead of `#ifdef` guard.


### Defining Functions in Header Files

Prefer defining functions in .cpp files. 
A function can be defined in a header in case it is very short, like a setter or a getter, or it must be defined
due to its template nature.

### Order of Includes
 * Related header
 * System headers - only system headers should be included using an angle-bracketed path
 * Project headers
  
# Scoping

* Do not use the `using namespace` directive.
* Place code in a namespace, with some exceptions:
  + Public C headers 
* Use anonymous namespaces for internal linkage when a definition should not be referenced from outside the .cpp file.

# Nonmember, Static Member, and Global Functions

* Prefer placing nonmember functions in a namespace.
* Do not group static members by placing them in a class.

# Local Variables

* Initialize all variables in the declaration.
* Prefer to keep a variable scope as short as possible.

# Global variables
  
* Do not use global variables, unless a global variable is `constexpr` and you really need it.
  
# Classes

### Constructors
 * Avoid virtual calls from constructor or destructor.
 * Prefer using `= default` for trivial constructors.
 * Prefer `noexcept` marked move constructors.
 * Prefer a `noexcept` marked constructor if it can't fail.
 * Constructors with one argument should be `explicit`.
  
### Inheritance
 * Use `public` inheritance; otherwise, prefer composition.
 * You may use `final` on classes when you don't intend to support using them as base classes.
 * Explicitly annotate all overridden methods with `override`.
 * Don't use `virtual` to declare an overridden method.
 * Use multiple inheritance only for pure interface.
 * Don't use default arguments for overridden methods.
 * Prefer not to use default arguments for virtual methods.
  
### Operator Overloading
 * Define overloaded operators only if their meaning is obvious, unsurprising, and consistent with the corresponding built-in operators.

### Declaration Order
    1. Types and type aliases
    2. Constructors
    3. Destructor
    4. Public methods
    5. Factory methods
    6. Private methods
    7. Data members

### Data members
 * Data members should be private,unless they are constants.

### Thread safety
 * All of a class's `const` methods should be safe to invoke concurrently with each other.

 # Structs 
 * Use `struct` only for simple data carriers.
 * All members should be public.

# Pairs and  tuples
* Use a struct instead of a pair or a tuple whenever the elements can have meaningful names.

# Functions
* Prefer using return values over output parameters.
* Return by value, smart pointer, or std::optional in case the function can fail.
* Prefer `noexcept` functions if possible.
* Use structs to pass a lot of parameters.
* Keep functions short
  
# Ownership
 * Use smart pointers instead of "raw" pointers.
 * Use `make_shared` and `make_unique` to create objects.
 * Leave a comment if you have no other option except using the `new` keyword.

# Exceptions 
 * Exceptions can be used only for unexpected failure handling.
 * Never use exceptions as control flow statements (same as `goto`).
 * Prefer providing the `noexcept` guarantees where possible.

# Run-Time Type Information (RTTI) and Casting
 * Use `dynamic_cast` with care.
 * Don't use the `typeid` keyword.
 * C-style casts are forbidden.
 * Don't use a pointer to a [bool implicit cast](https://clang.llvm.org/extra/clang-tidy/checks/readability/implicit-bool-conversion.html) `if (ptr){...}`.
 * Leave a comment if you need to use `reinterpret_cast`.
  
# Pre-Increment and Pre-Decrement

* Use the prefix form (++i) of the increment and decrement operators unless you need postfix semantics.

# Use of const

* Use `const` whenever it makes even a little sense.
* Prefer using `const` APIs.

# Integer Types
* Prefer [fixed-width integer types](https://en.cppreference.com/w/cpp/types/integer.html).

# Floating-Point Types
* Of the built-in C++ floating-point types, the only ones used are `float` and `double`. 

# Macros
* Avoid using macros; leave a comment if you have to use some.

# Using nullptr / NULL 

* Never compare a raw pointer with NULL or 0.
* Do not use NULL or 0 to initialize a pointer.

# sizeof 
* Prefer `sizeof(var_name)` to `sizeof(type)`.

# auto
* Use `auto` if it makes the code clearer to readers who aren't familiar with the project, or if it makes the code safer. 
* C++ code is usually clearer when types are explicit.
* Use `auto` with `make_shared`,`make_unique`,and `static_cast` (`auto var=std::make_shared<T>`).
  
# Lambda Expressions
* Do not use `[=]` caprute;prefer explicit captures.

# Type Aliases
* Prefer `using` instead `typedef`

# Switch Statements
* If not conditional on an enumerated value, `switch` statements should always have a default case.

# Naming

## Files
* Filenames should be all lowercase and can include underscores (`my_validator.hpp`). 
  
## Type Names
* Type names start with a capital letter and have a capital letter for each new word, with no underscores: `MySuperClass`

## Variable Names
*  The names of variables (including function parameters) and data members are `snake_case`.

## Class Data Members
 * Use the `snake_case` for member variables, but with a trailing underscore: `var_name_`.
 * Use  "k" followed by mixed case for static const members: `kMyConstant`.
  
## Struct Data Members
 * Use the `snake_case` for member variables.

## Constant Names
 * Variables declared constexpr or const, and whose value is fixed for the duration of the program, are named with a leading "k" followed by mixed case.

## Function Names
 * Use PascalCase; camelCase is also OK.

## Namespace Names
 * Namespace names are snake_case

## Enumerator Names  
 * Enumerators (for both scoped and unscoped enums) should be named like constants, not like macros. That is, use kEnumName, not ENUM_NAME. 
  `enum class MyEnum { kFirst, kSecond };`

## File Comments
 * Start each file with license boilerplate.

## TODO
 * TODOs should include the string `TODO` in all caps, followed by the bug ID, name, e-mail address, or other identifier of the person or issue with the best context about the problem referenced by the TODO (`TODO(bug 12345678)`). 

# Documentation Standards

## Required Documentation

### Mandatory for Public API
* All **public classes** and **public functions** MUST have Doxygen-style documentation comments.
* All public functions/methods
* All template classes/functions
* All enum types and constants
   
## Basic Syntax

### For Classes
```cpp
/**
 * @brief Manages user authentication and session handling
 * 
 * This class provides methods for user login, logout, and session
 * validation. It handles token generation and security checks.
 */
class AuthManager {
public:
    /**
     * @brief Authenticates a user with credentials
     * @param username The user's username
     * @param password The user's password
     * @return true if authentication successful, false otherwise
     */
    bool login(const std::string& username, const std::string& password);
    
    /**
     * @brief Terminates the current user session
     */
    void logout();
    
    /**
     * @brief Checks if current session is valid
     * @return true if session is active and valid
     */
    bool isSessionValid() const;
};
```
### For Functions

```cpp
/**
 * @brief Brief description of what the function does
 * 
 * @param param1 Description of first parameter
 * @param param2 Description of second parameter
 * @return Description of return value
 */
int functionName(int param1, int param2);
```

# Code Formatting

### Formatting tool

* Use the **clang-format** tool.
* Configure your IDE enable **format-on-save**.

### Formatting style

Settings for the **clang-format** can be found in the [.clang-format](.clang-format) file.

All settings explanations can be found [here](https://clang.llvm.org/docs/ClangFormatStyleOptions.html).

This style is based on the Google code formatting style.

### Line Length
* Each line of text in your code should be at most 80 characters long.
  
### Spaces and Alignment
* We use spaces for indentation. Do not use tabs in your code. Set your editor to emit spaces when you hit the tab key.
* Indentation: 4 spaces (no tabs)
* Space Before Parentheses: Only for control statements
```cpp
  if (condition) {    // space before (
    function();         // no space before (
```
* Trailing Comments: Aligned with 2 spaces before comment.
* Function Parameters: Can be packed on same line.

### Pointer Alignment**
* Left (`int* ptr`)    

### Looping and branching statements
* ALL bodies of if statements and loops (`for`, `do`, `while`, and `while`) should be [inside braces](https://clang.llvm.org/extra/clang-tidy/checks/readability/braces-around-statements.html).
  
### Braces and Blocks
* **Brace Style**: Attached
```cpp
void function() {
    // braces on same line
}
```
* Short Functions: Allowed on single line.
* Short If Statements: Without else clause can be single line.
* Short Loops: Allowed on single line


### Variable and Array Initialization
* You may choose between =, (), and {}; the following are all correct


### Function Formatting
```cpp
// Short function on one line
void shortFunc() { return; }

// Longer function broken
void longerFunction(int param1, int param2,
                    int param3) {
    // body
}
```

### Class formatting
```cpp
class MyClass {
public:     // access modifier aligned left
    MyClass();
    
private:
    int member;
};
```