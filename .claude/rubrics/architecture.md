# Architecture review rubric

Applied by `architect-reviewer` on every PR. The reviewer picks the 3-5 highest-impact items — never enumerates the full list.

## Section A: Design pattern conformance

- If a new class has multiple implementations across the codebase, a Protocol is defined and the class satisfies it
- Long if/elif/else chains keyed on type are refactored to dispatch tables or polymorphism
- State machines disguised as nested conditionals are identified (suggest enum + transition table)
- Singleton patterns are explicit (not just module globals)
- Factory functions used for object construction with complex initialization

## Section B: Modularity and separation of concerns

- Side effects separated from logic (pure functions returning data; effectful functions taking data and returning None)
- I/O at boundaries, not in the middle of business logic
- Configuration injected via parameters, not read at deep call sites
- No business logic in `__init__` methods (no DB calls, no network calls, no file I/O)
- Test helpers separated from test cases (in `conftest.py` or `fixtures/`)

## Section C: Public API design

- New public functions have docstrings explaining contract (parameters, return, raises, examples)
- Public functions accept narrow input types (not bare `dict`, bare `str` — use `TypedDict`, `Literal`, custom types)
- Public functions return narrow output types (not `Any`, not `Optional` unless truly optional)
- Error conditions communicated via specific exceptions or Result types, not None-on-failure unless documented

## Section D: Extension points

- New features that vary by case use the Strategy or Visitor pattern, not switch-on-type
- New types of things added by composition (registering with a registry) rather than modifying existing dispatch code
- Plugin-like surfaces use Protocols for typing, not abstract base classes (Protocols are structural, more flexible)

## Section E: Anti-patterns to call out

- God classes (single class doing 5+ unrelated things)
- Train wreck calls (`a.b.c.d.e.f`) suggesting Demeter violations
- Mutable default arguments (`def f(x=[]):`)
- Catching bare `Exception` or `BaseException`
- `eval`/`exec` in non-test code
- Type hints lying (says `str`, actually accepts `bytes` too)
